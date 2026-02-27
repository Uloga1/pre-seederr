package main

import (
	"bytes"
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

	"github.com/jackpal/bencode-go"
)

const (
	Port       = ":5000"
	ConfigPath = "data/config.json"
)

type Config struct {
	ProwlarrURL     string  `json:"prowlarr_url"`
	ProwlarrAPIKey  string  `json:"prowlarr_api_key"`
	SizeToleranceMB float64 `json:"size_tolerance_mb"`
	QbitURL         string  `json:"qbit_url"`
	QbitUser        string  `json:"qbit_user"`
	QbitPass        string  `json:"qbit_pass"`
	QbitSavePath    string  `json:"qbit_save_path"`
}

var AppConfig Config

func loadConfig() {
	os.MkdirAll(filepath.Dir(ConfigPath), 0755)
	file, err := os.ReadFile(ConfigPath)
	if err != nil {
		AppConfig = Config{
			ProwlarrURL:     "http://192.168.1.100:9696",
			ProwlarrAPIKey:  "",
			SizeToleranceMB: 5.0,
			QbitURL:         "http://192.168.1.100:8080",
			QbitUser:        "admin",
			QbitPass:        "adminadmin",
			QbitSavePath:    "/downloads/pre-seeds",
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

type PageData struct {
	Error           string
	Success         string
	Name            string
	TargetSize      float64
	Matches         []Match
	Config          Config
	EncodedTorrentA string
}

func main() {
	loadConfig()

	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/settings", handleSettings)
	http.HandleFunc("/inject", handleInject)
	
	// New Test Routes
	http.HandleFunc("/test-prowlarr", handleTestProwlarr)
	http.HandleFunc("/test-qbit", handleTestQbit)

	fmt.Printf("[*] Go Pre-Seederr running on port %s\n", Port)
	http.ListenAndServe(Port, nil)
}

// --- Test Connection Handlers ---
func handleTestProwlarr(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		return
	}
	pURL := r.FormValue("prowlarr_url")
	pAPI := r.FormValue("prowlarr_api_key")

	// Prowlarr System Status API
	testURL := fmt.Sprintf("%s/api/v1/system/status?apikey=%s", pURL, pAPI)
	resp, err := http.Get(testURL)
	if err != nil || resp.StatusCode != 200 {
		http.Error(w, "Failed", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func handleTestQbit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		return
	}
	qURL := r.FormValue("qbit_url")
	qUser := r.FormValue("qbit_user")
	qPass := r.FormValue("qbit_pass")

	data := url.Values{"username": {qUser}, "password": {qPass}}
	resp, err := http.PostForm(qURL+"/api/v2/auth/login", data)
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

// --- qBittorrent API Logic ---
func qbitLogin() (*http.Cookie, error) {
	data := url.Values{"username": {AppConfig.QbitUser}, "password": {AppConfig.QbitPass}}
	resp, err := http.PostForm(AppConfig.QbitURL+"/api/v2/auth/login", data)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	for _, cookie := range resp.Cookies() {
		if cookie.Name == "SID" {
			return cookie, nil
		}
	}
	return nil, fmt.Errorf("authentication failed")
}

func qbitAddURL(cookie *http.Cookie, dlURL string) error {
	data := url.Values{
		"urls":     {dlURL},
		"savepath": {AppConfig.QbitSavePath},
	}

	req, err := http.NewRequest("POST", AppConfig.QbitURL+"/api/v2/torrents/add", strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("qBit URL inject status %d", resp.StatusCode)
	}
	return nil
}

func qbitAddFile(cookie *http.Cookie, fileBytes []byte) error {
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	part, err := writer.CreateFormFile("torrents", "trackerA.torrent")
	if err != nil {
		return err
	}
	part.Write(fileBytes)

	writer.WriteField("savepath", AppConfig.QbitSavePath)
	writer.WriteField("paused", "true")
	writer.Close()

	req, err := http.NewRequest("POST", AppConfig.QbitURL+"/api/v2/torrents/add", body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.AddCookie(cookie)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("qBit File inject status %d", resp.StatusCode)
	}
	return nil
}

// --- Handlers ---
func handleInject(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	dlURL := r.FormValue("download_url")
	b64Torrent := r.FormValue("torrent_data")
	
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

	err = qbitAddURL(cookie, dlURL)
	if err != nil {
		http.Redirect(w, r, "/?err="+url.QueryEscape("Failed injecting Tracker B: "+err.Error()), http.StatusSeeOther)
		return
	}

	err = qbitAddFile(cookie, torrentBytes)
	if err != nil {
		http.Redirect(w, r, "/?err="+url.QueryEscape("Tracker B started, but failed injecting Tracker A: "+err.Error()), http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/?msg="+url.QueryEscape("Success! Tracker B is downloading, Tracker A is paused."), http.StatusSeeOther)
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

		if err := saveConfig(); err != nil {
			data.Error = "Failed to save settings."
		} else {
			data.Success = "Settings saved successfully!"
			data.Config = AppConfig
		}
	}
	tmpl.Execute(w, data)
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("templates/index.html"))
	data := PageData{}

	if msg := r.URL.Query().Get("msg"); msg != "" {
		data.Success = msg
	}
	if errMsg := r.URL.Query().Get("err"); errMsg != "" {
		data.Error = errMsg
	}

	if r.Method == http.MethodPost {
		file, _, err := r.FormFile("torrent_file")
		if err != nil {
			data.Error = "Failed to read uploaded file."
			tmpl.Execute(w, data)
			return
		}
		defer file.Close()

		fileBytes, _ := io.ReadAll(file)
		data.EncodedTorrentA = base64.StdEncoding.EncodeToString(fileBytes)

		name, targetSize, err := parseTorrent(fileBytes)
		if err != nil {
			data.Error = "Invalid .torrent file."
			tmpl.Execute(w, data)
			return
		}

		data.Name = name
		data.TargetSize = float64(targetSize) / (1024 * 1024)

		results, err := searchProwlarr(name)
		if err != nil {
			data.Error = "Failed to connect to Prowlarr."
			tmpl.Execute(w, data)
			return
		}

		data.Matches = findBestMatches(results, targetSize, AppConfig.SizeToleranceMB)
	}
	tmpl.Execute(w, data)
}

func parseTorrent(data []byte) (string, int64, error) {
	reader := bytes.NewReader(data)
	decoded, err := bencode.Decode(reader)
	if err != nil {
		return "", 0, err
	}

	torrentMap, ok := decoded.(map[string]interface{})
	if !ok {
		return "", 0, fmt.Errorf("invalid format")
	}

	info, ok := torrentMap["info"].(map[string]interface{})
	if !ok {
		return "", 0, fmt.Errorf("no info dict")
	}

	name := info["name"].(string)
	var totalSize int64

	if length, ok := info["length"].(int64); ok {
		totalSize = length
	} else if files, ok := info["files"].([]interface{}); ok {
		for _, file := range files {
			f := file.(map[string]interface{})
			totalSize += f["length"].(int64)
		}
	}
	return name, totalSize, nil
}

func searchProwlarr(query string) ([]ProwlarrResult, error) {
	url := fmt.Sprintf("%s/api/v1/search?query=%s&type=search&apikey=%s", AppConfig.ProwlarrURL, url.QueryEscape(query), AppConfig.ProwlarrAPIKey)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Prowlarr returned status %d", resp.StatusCode)
	}

	var results []ProwlarrResult
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		return nil, err
	}
	return results, nil
}

func findBestMatches(results []ProwlarrResult, targetSize int64, toleranceMB float64) []Match {
	toleranceBytes := int64(toleranceMB * 1024 * 1024)
	var matches []Match

	for _, res := range results {
		diff := res.Size - targetSize
		if diff < 0 {
			diff = -diff
		}

		if diff <= toleranceBytes {
			matches = append(matches, Match{
				Title:       res.Title,
				Indexer:     res.Indexer,
				SizeMB:      float64(res.Size) / (1024 * 1024),
				DownloadURL: res.DownloadURL,
				SizeDiffMB:  float64(diff) / (1024 * 1024),
			})
		}
	}

	sort.Slice(matches, func(i, j int) bool {
		return matches[i].SizeDiffMB < matches[j].SizeDiffMB
	})
	return matches
}