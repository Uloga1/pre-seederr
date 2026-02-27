package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jackpal/bencode-go"
)

const (
	Port       = ":5000"
	ConfigPath = "data/config.json"
)

type Config struct {
	ProwlarrURL      string  `json:"prowlarr_url"`
	ProwlarrAPIKey   string  `json:"prowlarr_api_key"`
	SizeToleranceMB  float64 `json:"size_tolerance_mb"`
	QbitURL          string  `json:"qbit_url"`
	QbitUser         string  `json:"qbit_user"`
	QbitPass         string  `json:"qbit_pass"`
	QbitSavePath     string  `json:"qbit_save_path"`
	QbitCategories   string  `json:"qbit_categories"`
	QbitSkipChecking bool    `json:"qbit_skip_checking"`
}

var AppConfig Config

func loadConfig() {
	os.MkdirAll(filepath.Dir(ConfigPath), 0755)
	file, err := os.ReadFile(ConfigPath)
	if err != nil {
		AppConfig = Config{
			ProwlarrURL:      "http://192.168.1.100:9696",
			ProwlarrAPIKey:   "",
			SizeToleranceMB:  5.0,
			QbitURL:          "http://192.168.1.100:8080",
			QbitUser:         "admin",
			QbitPass:         "adminadmin",
			QbitSavePath:     "/downloads/pre-seeds",
			QbitCategories:   "movies, tv, music",
			QbitSkipChecking: false,
		}
		saveConfig()
		return
	}
	json.Unmarshal(file, &AppConfig)
}

func saveConfig() error {
	data, err := json.MarshalIndent(AppConfig, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(ConfigPath, data, 0644)
}

type ProwlarrResult struct {
	Title       string `json:"title"`
	Indexer     string `json:"indexer"`
	Size        int64  `json:"size"`
	DownloadURL string `json:"downloadUrl"`
}

type Match struct {
	Title       string
	Indexer     string
	SizeMB      float64
	DownloadURL string
	SizeDiffMB  float64
}

type TorrentResult struct {
	FileName        string
	Name            string
	TargetSize      float64
	Matches         []Match
	EncodedTorrentA string
	Error           string
}

type PageData struct {
	GlobalError   string
	GlobalSuccess string
	Results       []TorrentResult
	Config        Config
	Categories    []string
}

func main() {
	loadConfig()

	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/settings", handleSettings)
	http.HandleFunc("/inject", handleInject)
	http.HandleFunc("/test-prowlarr", handleTestProwlarr)
	http.HandleFunc("/test-qbit", handleTestQbit)

	fmt.Printf("[*] Go Pre-Seederr running on port %s\n", Port)
	http.ListenAndServe(Port, nil)
}

func handleTestProwlarr(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { return }
	testURL := fmt.Sprintf("%s/api/v1/system/status?apikey=%s", r.FormValue("prowlarr_url"), r.FormValue("prowlarr_api_key"))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		http.Error(w, "Failed", http.StatusBadRequest)
		return
	}
	defer resp.Body.Close()
	w.WriteHeader(http.StatusOK)
}

func handleTestQbit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { return }
	data := url.Values{"username": {r.FormValue("qbit_user")}, "password": {r.FormValue("qbit_pass")}}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "POST", r.FormValue("qbit_url")+"/api/v2/auth/login", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, "Failed", http.StatusBadRequest)
		return
	}
	defer resp.Body.Close()
	bodyBytes, _ := io.ReadAll(resp.Body)
	if string(bodyBytes) != "Ok." {
		http.Error(w, "Failed", http.StatusUnauthorized)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func qbitLogin() (*http.Cookie, error) {
	data := url.Values{"username": {AppConfig.QbitUser}, "password": {AppConfig.QbitPass}}
	resp, err := http.PostForm(AppConfig.QbitURL+"/api/v2/auth/login", data)
	if err != nil { return nil, err }
	defer resp.Body.Close()
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "SID" { return cookie, nil }
	}
	return nil, fmt.Errorf("authentication failed")
}

func qbitAddURL(cookie *http.Cookie, dlURL string, category string) error {
	data := url.Values{"urls": {dlURL}, "savepath": {AppConfig.QbitSavePath}}
	if category != "" { data.Set("category", category) }
	req, _ := http.NewRequest("POST", AppConfig.QbitURL+"/api/v2/torrents/add", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil { return err }
	defer resp.Body.Close()
	return nil
}

func qbitAddFile(cookie *http.Cookie, fileBytes []byte, category string) error {
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, _ := writer.CreateFormFile("torrents", "trackerA.torrent")
	part.Write(fileBytes)
	writer.WriteField("savepath", AppConfig.QbitSavePath)
	writer.WriteField("paused", "true")
	if AppConfig.QbitSkipChecking { writer.WriteField("skip_checking", "true") }
	if category != "" { writer.WriteField("category", category) }
	writer.Close()
	req, _ := http.NewRequest("POST", AppConfig.QbitURL+"/api/v2/torrents/add", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.AddCookie(cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil { return err }
	defer resp.Body.Close()
	return nil
}

func handleInject(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { http.Redirect(w, r, "/", http.StatusSeeOther); return }
	dlURL := r.FormValue("download_url")
	b64Torrent := r.FormValue("torrent_data")
	category := r.FormValue("category")
	torrentBytes, err := base64.StdEncoding.DecodeString(b64Torrent)
	if err != nil {
		http.Redirect(w, r, "/?err="+url.QueryEscape("Failed to decode base64 torrent."), http.StatusSeeOther)
		return
	}
	cookie, err := qbitLogin()
	if err != nil {
		http.Redirect(w, r, "/?err="+url.QueryEscape("qBit Login Error: "+err.Error()), http.StatusSeeOther)
		return
	}
	_ = qbitAddURL(cookie, dlURL, category)
	_ = qbitAddFile(cookie, torrentBytes, category)
	http.Redirect(w, r, "/?msg="+url.QueryEscape("Success! Torrents injected."), http.StatusSeeOther)
}

func handleSettings(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("templates/settings.html"))
	data := PageData{Config: AppConfig}
	if r.Method == http.MethodPost {
		r.ParseForm()
		AppConfig.ProwlarrURL = r.FormValue("prowlarr_url")
		AppConfig.ProwlarrAPIKey = r.FormValue("prowlarr_api_key")
		fmt.Sscanf(r.FormValue("size_tolerance_mb"), "%f", &AppConfig.SizeToleranceMB)
		AppConfig.QbitURL = r.FormValue("qbit_url")
		AppConfig.QbitUser = r.FormValue("qbit_user")
		AppConfig.QbitPass = r.FormValue("qbit_pass")
		AppConfig.QbitSavePath = r.FormValue("qbit_save_path")
		AppConfig.QbitCategories = r.FormValue("qbit_categories")
		AppConfig.QbitSkipChecking = r.FormValue("qbit_skip_checking") == "on"
		saveConfig()
		data.GlobalSuccess = "Settings saved!"
		data.Config = AppConfig
	}
	tmpl.Execute(w, data)
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("templates/index.html"))
	data := PageData{}
	var catList []string
	if AppConfig.QbitCategories != "" {
		for _, cat := range strings.Split(AppConfig.QbitCategories, ",") {
			if c := strings.TrimSpace(cat); c != "" { catList = append(catList, c) }
		}
	}
	data.Categories = catList
	if msg := r.URL.Query().Get("msg"); msg != "" { data.GlobalSuccess = msg }
	if errMsg := r.URL.Query().Get("err"); errMsg != "" { data.GlobalError = errMsg }

	if r.Method == http.MethodPost {
		_ = r.ParseMultipartForm(50 << 20)
		files := r.MultipartForm.File["torrent_files"]
		var results []TorrentResult
		for _, fileHeader := range files {
			res := TorrentResult{FileName: fileHeader.Filename}
			file, err := fileHeader.Open()
			if err != nil { res.Error = "Read Error"; results = append(results, res); continue }
			fileBytes, _ := io.ReadAll(file)
			file.Close()
			res.EncodedTorrentA = base64.StdEncoding.EncodeToString(fileBytes)
			name, targetSize, err := parseTorrent(fileBytes)
			if err != nil { res.Error = "Parse Error"; results = append(results, res); continue }
			res.Name = name
			res.TargetSize = float64(targetSize) / (1024 * 1024)
			prowlarrMatches, err := searchProwlarr(name)
			if err != nil { res.Error = err.Error(); results = append(results, res); continue }
			res.Matches = findBestMatches(prowlarrMatches, targetSize, AppConfig.SizeToleranceMB)
			results = append(results, res)
		}
		data.Results = results
	}
	tmpl.Execute(w, data)
}

func searchProwlarr(query string) ([]ProwlarrResult, error) {
	// 5 Minute timeout to prevent any local or proxy drops
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	
	pUrl := fmt.Sprintf("%s/api/v1/search?query=%s&type=search&apikey=%s", AppConfig.ProwlarrURL, url.QueryEscape(query), AppConfig.ProwlarrAPIKey)
	req, _ := http.NewRequestWithContext(ctx, "GET", pUrl, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil { return nil, err }
	defer resp.Body.Close()
	if resp.StatusCode != 200 { return nil, fmt.Errorf("Status %d", resp.StatusCode) }
	var results []ProwlarrResult
	json.NewDecoder(resp.Body).Decode(&results)
	return results, nil
}

func parseTorrent(data []byte) (string, int64, error) {
	reader := bytes.NewReader(data)
	decoded, _ := bencode.Decode(reader)
	torrentMap := decoded.(map[string]interface{})
	info := torrentMap["info"].(map[string]interface{})
	name := info["name"].(string)
	var totalSize int64
	if length, ok := info["length"].(int64); ok {
		totalSize = length
	} else {
		for _, file := range info["files"].([]interface{}) {
			totalSize += file.(map[string]interface{})["length"].(int64)
		}
	}
	return name, totalSize, nil
}

func findBestMatches(results []ProwlarrResult, targetSize int64, toleranceMB float64) []Match {
	toleranceBytes := int64(toleranceMB * 1024 * 1024)
	var matches []Match
	for _, res := range results {
		diff := res.Size - targetSize
		if diff < 0 { diff = -diff }
		if diff <= toleranceBytes {
			matches = append(matches, Match{Title: res.Title, Indexer: res.Indexer, SizeMB: float64(res.Size) / (1024 * 1024), DownloadURL: res.DownloadURL, SizeDiffMB: float64(diff) / (1024 * 1024)})
		}
	}
	sort.Slice(matches, func(i, j int) bool { return matches[i].SizeDiffMB < matches[j].SizeDiffMB })
	return matches
}