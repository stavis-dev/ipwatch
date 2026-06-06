package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// IPRecord представляет строку данных для сохранения
type IPRecord struct {
	Timestamp string
	IP        string
	ISP       string
	Comment   string
}

// Config описывает структуру JSON-конфигурации
type Config struct {
	Storage struct {
		LogPath string `json:"log_path"`
	} `json:"storage"`
	ISPNormalization map[string]string `json:"isp_normalization"`
}

var defaultISPNormalization = map[string]string{
	"PJSC MegaFon":                         "MegaFon",
	"International Hosting Company Limited": "NUXT",
	"Mobile TeleSystems":                   "MTS",
	"16345 Mobile Region":                  "Beeline",
}

const (
	colorSuccess = "\033[92m"
	colorWarning = "\033[93m"
	colorReset   = "\033[0m"
	logFilename  = "ipwatch_log.csv"
)

func wrapColor(text, color string) string {
	return color + text + colorReset
}

func getConfigPath() string {
	configFilename := "ipwatch.json"
	home, _ := os.UserHomeDir()

	switch runtime.GOOS {
	case "windows":
		appData := os.Getenv("APPDATA")
		if appData == "" {
			appData = home
		}
		return filepath.Join(appData, "ipwatch", configFilename)
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "ipwatch", configFilename)
	default: // Linux и другие Unix-подобные (XDG)
		xdgConfig := os.Getenv("XDG_CONFIG_HOME")
		if xdgConfig == "" {
			xdgConfig = filepath.Join(home, ".config")
		}
		return filepath.Join(xdgConfig, "ipwatch", configFilename)
	}
}

func loadConfig(path string) *Config {
	cfg := &Config{}
	cfg.ISPNormalization = make(map[string]string)
	for k, v := range defaultISPNormalization {
		cfg.ISPNormalization[k] = v
	}

	file, err := os.Open(path)
	if err != nil {
		return cfg // Если файла нет, возвращаем дефолтные настройки ISP
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to parse config JSON: %v. Using defaults.\n", err)
	}

	if len(cfg.ISPNormalization) == 0 {
		cfg.ISPNormalization = defaultISPNormalization
	}

	return cfg
}

func getLogPath(cfg *Config) string {
	if cfg != nil && cfg.Storage.LogPath != "" {
		path := cfg.Storage.LogPath
		if strings.HasPrefix(path, "~") {
			home, _ := os.UserHomeDir()
			path = filepath.Join(home, path[1:])
		}
		abs, err := filepath.Abs(path)
		if err == nil {
			return abs
		}
		return path
	}

	home, _ := os.UserHomeDir()

	if runtime.GOOS == "windows" {
		docs := filepath.Join(home, "Documents")
		if _, err := os.Stat(docs); err == nil {
			return filepath.Join(docs, logFilename)
		}
	}

	docsPath := filepath.Join(home, "Documents")
	if _, err := os.Stat(docsPath); err == nil {
		return filepath.Join(docsPath, logFilename)
	}

	fallbackDir := filepath.Join(home, ".ipwatch")
	_ = os.MkdirAll(fallbackDir, 0755)
	return filepath.Join(fallbackDir, logFilename)
}

func normalizeISP(name string, rules map[string]string) string {
	clean := strings.TrimSpace(name)
	for pattern, canonical := range rules {
		if strings.Contains(clean, pattern) {
			return canonical
		}
	}
	return name
}

// Сетевые запросы
func fetchURL(url string, timeout time.Duration) (map[string]interface{}, error) {
	client := http.Client{Timeout: timeout}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}
	return data, nil
}

func fetchIPFast() (map[string]interface{}, error) {
	providers := []string{
		"https://api.ipify.org?format=json",
		"https://ifconfig.me/all.json",
	}
	for _, url := range providers {
		if data, err := fetchURL(url, 2*time.Second); err == nil {
			ip, _ := data["ip"].(string)
			if ip == "" {
				ip, _ = data["query"].(string)
			}
			if ip == "" {
				ip, _ = data["address"].(string)
			}
			if ip != "" {
				return map[string]interface{}{"query": ip, "isp": "N/A"}, nil
			}
		}
	}
	return nil, fmt.Errorf("all fast IP providers failed")
}

func fetchIPFull() (map[string]interface{}, error) {
	providers := []string{
		"http://ip-api.com/json/?fields=query,isp",
		"https://ipinfo.io/json",
		"https://ipwho.is",
	}
	for _, url := range providers {
		if data, err := fetchURL(url, 3*time.Second); err == nil {
			ip, _ := data["query"].(string)
			if ip == "" {
				ip, _ = data["ip"].(string)
			}
			if ip == "" {
				ip, _ = data["address"].(string)
			}

			isp, _ := data["isp"].(string)
			if isp == "" {
				isp, _ = data["org"].(string)
			}
			if isp == "" {
				isp = "N/A"
			}

			if ip != "" {
				return map[string]interface{}{"query": ip, "isp": isp}, nil
			}
		}
	}
	return nil, fmt.Errorf("all full IP providers failed")
}

func fetchIPForCustom(ip string) map[string]interface{} {
	providers := []string{
		fmt.Sprintf("http://ip-api.com/json/%s?fields=query,isp", ip),
		fmt.Sprintf("https://ipinfo.io/%s/json", ip),
		fmt.Sprintf("https://ipwho.is/%s", ip),
	}
	for _, url := range providers {
		if data, err := fetchURL(url, 3*time.Second); err == nil {
			foundIP, _ := data["query"].(string)
			if foundIP == "" {
				foundIP, _ = data["ip"].(string)
			}
			isp, _ := data["isp"].(string)
			if isp == "" {
				isp, _ = data["org"].(string)
			}
			if isp == "" {
				isp = "N/A"
			}
			if foundIP != "" {
				return map[string]interface{}{"query": foundIP, "isp": isp}
			}
		}
	}
	return map[string]interface{}{"query": ip, "isp": "N/A"}
}

// renderTable генерирует таблицу с ограничением разделителя по ширине
func renderTable(headers []string, rows [][]string) string {
	if len(headers) == 0 {
		return ""
	}

	// Считаем ширины колонок по контенту
	colWidths := make([]int, len(headers))
	for i, h := range headers {
		colWidths[i] = len(h)
	}
	for _, row := range rows {
		for i, val := range row {
			if i < len(colWidths) && len(val) > colWidths[i] {
				colWidths[i] = len(val)
			}
		}
	}

	// Функция для сборки одной строки таблицы
	buildRow := func(cols []string) string {
		var lineParts []string
		for i, val := range cols {
			if i < len(cols)-1 {
				// Первые три колонки выравниваем пробелами по ширине
				lineParts = append(lineParts, fmt.Sprintf("%-*s", colWidths[i], val))
			} else {
				// Последнюю колонку (Comment) выводим как есть
				lineParts = append(lineParts, val)
			}
		}
		return strings.Join(lineParts, " | ")
	}

	var renderedRows []string
	
	// Рендерим заголовок и строки данных
	headerLine := buildRow(headers)
	renderedRows = append(renderedRows, headerLine)

	maxLineLen := len(headerLine)
	for _, row := range rows {
		line := buildRow(row)
		renderedRows = append(renderedRows, line)
		if len(line) > maxLineLen {
			maxLineLen = len(line)
		}
	}

	// Ограничиваем длину разделительной линии (не длиннее 80 знаков)
	if maxLineLen > 80 {
		maxLineLen = 80
	}

	sep := strings.Repeat("-", maxLineLen)

	var sb strings.Builder
	sb.WriteString(sep + "\n")
	sb.WriteString(renderedRows[0] + "\n") // Заголовок
	sb.WriteString(sep + "\n")
	
	for _, r := range renderedRows[1:] {   // Строки
		sb.WriteString(r + "\n")
	}
	sb.WriteString(sep)

	return sb.String()
}

func main() {
	commentFlag := flag.String("c", "", "Save current IP with a comment")
	saveFlag := flag.Bool("s", false, "Save current IP without comment")
	listFlag := flag.Bool("l", false, "Show all logged IPs")
	logPathFlag := flag.Bool("log-path", false, "Show log file path")
	cfgPathFlag := flag.Bool("cfg-path", false, "Show config file path")
	tableFlag := flag.Bool("t", false, "Show detailed table output")
	customIPFlag := flag.String("i", "", "Use custom IP instead of fetching")
	flag.Parse()

	cfgPath := getConfigPath()
	if *cfgPathFlag {
		fmt.Println(cfgPath)
		return
	}

	cfg := loadConfig(cfgPath)
	logPath := getLogPath(cfg)

	if *logPathFlag {
		fmt.Println(logPath)
		return
	}

	fileExisted := true
	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		fileExisted = false
		_ = os.MkdirAll(filepath.Dir(logPath), 0755)
	}

	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening log file: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	writer := csv.NewWriter(f)
	writer.Comma = '\t'

	if !fileExisted {
		_ = writer.Write([]string{"Timestamp", "IP Address", "ISP", "Comment"})
		writer.Flush()
	}

	rf, err := os.Open(logPath)
	var allRows [][]string
	if err == nil {
		reader := csv.NewReader(rf)
		reader.Comma = '\t'
		records, _ := reader.ReadAll()
		if len(records) > 1 {
			allRows = records[1:]
		}
		rf.Close()
	}

	if *listFlag {
		if len(allRows) == 0 {
			fmt.Fprintln(os.Stderr, "No IP records found.")
			return
		}
		fmt.Fprintln(os.Stderr, renderTable([]string{"Timestamp", "IP Address", "ISP", "Comment"}, allRows))
		return
	}

	shouldSave := *saveFlag || *commentFlag != ""
	var raw map[string]interface{}

	if *customIPFlag != "" {
		if shouldSave {
			raw = fetchIPForCustom(*customIPFlag)
		} else {
			raw = map[string]interface{}{"query": *customIPFlag, "isp": "Manual"}
		}
	} else {
		var err error
		if *tableFlag || shouldSave {
			raw, err = fetchIPFull()
		} else {
			raw, err = fetchIPFast()
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	}

	rawISP, _ := raw["isp"].(string)
	isp := normalizeISP(rawISP, cfg.ISPNormalization)
	ip, _ := raw["query"].(string)
	comment := *commentFlag
	if comment == "" {
		comment = "N/A"
	}

	record := IPRecord{
		Timestamp: time.Now().Format("2006-01-02 15:04"),
		IP:        ip,
		ISP:       isp,
		Comment:   comment,
	}

	isNew := true
	var matches [][]string
	for _, row := range allRows {
		if len(row) >= 2 && row[1] == record.IP {
			isNew = false
			if *tableFlag {
				matches = append(matches, row)
			}
		}
	}

	color := colorWarning
	status := "used before"
	if isNew {
		color = colorSuccess
		status = "new"
	}

	if *tableFlag {
		headers := []string{"Timestamp", "IP Address", "ISP", "Comment"}
		rows := [][]string{{record.Timestamp, record.IP, record.ISP, record.Comment}}
		tableOutput := renderTable(headers, rows)
		tableOutput = strings.ReplaceAll(tableOutput, record.IP, wrapColor(record.IP, color))
		fmt.Fprintln(os.Stderr, tableOutput)

		if len(matches) > 0 {
			fmt.Fprintln(os.Stderr, "\n⚠️  IP matches found:")
			fmt.Fprintln(os.Stderr, renderTable(headers, matches))
		}
	} else {
		fmt.Fprintf(os.Stderr, "IP: %s (%s)\n", wrapColor(record.IP, color), status)
	}

	if shouldSave {
		err := writer.Write([]string{record.Timestamp, record.IP, record.ISP, record.Comment})
		if err == nil {
			writer.Flush()
			fmt.Fprintln(os.Stderr, "✅ IP saved to log.")
		}
	}

	if isNew {
		os.Exit(0)
	}
	os.Exit(1)
}