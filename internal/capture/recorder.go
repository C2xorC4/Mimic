package capture

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// CapturedResponse represents a captured network response
type CapturedResponse struct {
	Name       string    `yaml:"name"`
	Service    string    `yaml:"service"`
	CapturedAt time.Time `yaml:"captured_at"`
	SourceOS   string    `yaml:"source_os"`
	SourceIP   string    `yaml:"source_ip"`
	Protocol   string    `yaml:"protocol"`
	Port       uint16    `yaml:"port"`
	ProbeHex   string    `yaml:"probe_hex"`
	ResponseHex string   `yaml:"response_hex"`
	Notes      string    `yaml:"notes,omitempty"`
}

// Recorder captures and stores network responses
type Recorder struct {
	outputDir string
	service   string
	sourceOS  string
}

// NewRecorder creates a new response recorder
func NewRecorder(outputDir, service, sourceOS string) (*Recorder, error) {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return nil, fmt.Errorf("creating output directory: %w", err)
	}

	return &Recorder{
		outputDir: outputDir,
		service:   service,
		sourceOS:  sourceOS,
	}, nil
}

// Record saves a captured probe/response pair
func (r *Recorder) Record(name string, protocol string, port uint16, sourceIP string, probe, response []byte) error {
	captured := CapturedResponse{
		Name:        name,
		Service:     r.service,
		CapturedAt:  time.Now(),
		SourceOS:    r.sourceOS,
		SourceIP:    sourceIP,
		Protocol:    protocol,
		Port:        port,
		ProbeHex:    hex.EncodeToString(probe),
		ResponseHex: hex.EncodeToString(response),
	}

	// Save metadata as YAML
	metaPath := filepath.Join(r.outputDir, fmt.Sprintf("%s.yaml", name))
	metaData, err := yaml.Marshal(&captured)
	if err != nil {
		return fmt.Errorf("marshaling metadata: %w", err)
	}
	if err := os.WriteFile(metaPath, metaData, 0644); err != nil {
		return fmt.Errorf("writing metadata: %w", err)
	}

	// Save raw response as binary
	binPath := filepath.Join(r.outputDir, fmt.Sprintf("%s.bin", name))
	if err := os.WriteFile(binPath, response, 0644); err != nil {
		return fmt.Errorf("writing response binary: %w", err)
	}

	return nil
}

// LoadCapture loads a previously captured response
func LoadCapture(path string) (*CapturedResponse, []byte, error) {
	metaData, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("reading metadata: %w", err)
	}

	var captured CapturedResponse
	if err := yaml.Unmarshal(metaData, &captured); err != nil {
		return nil, nil, fmt.Errorf("parsing metadata: %w", err)
	}

	response, err := hex.DecodeString(captured.ResponseHex)
	if err != nil {
		return nil, nil, fmt.Errorf("decoding response: %w", err)
	}

	return &captured, response, nil
}

// ConvertToBinary converts a captured response's hex to binary file
func ConvertToBinary(yamlPath, binPath string) error {
	captured, response, err := LoadCapture(yamlPath)
	if err != nil {
		return err
	}

	if err := os.WriteFile(binPath, response, 0644); err != nil {
		return fmt.Errorf("writing binary: %w", err)
	}

	fmt.Printf("Converted %s (%d bytes) to %s\n", captured.Name, len(response), binPath)
	return nil
}
