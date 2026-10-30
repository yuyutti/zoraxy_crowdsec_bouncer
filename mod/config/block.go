package config

import "errors"

type BlockResponseConfig struct {
	StatusCode int    `yaml:"status_code"`
	Page       string `yaml:"page"`
	CustomPage string `yaml:"custom_page"`
}

func (b *BlockResponseConfig) Validate() error {
	if b.StatusCode == 0 {
		b.StatusCode = 403
	}
	if b.Page == "" {
		b.Page = "default"
	}
	// Narrow allowlist avoids codes with challenge, retry or protocol contracts.
	if b.StatusCode != 403 && b.StatusCode != 418 && b.StatusCode != 451 && b.StatusCode != 503 {
		return errors.New("block_response.status_code must be 403, 418, 451 or 503")
	}
	if b.Page != "default" && b.Page != "evil" && b.Page != "custom" {
		return errors.New("unknown block_response.page")
	}
	if (b.Page == "custom") != (b.CustomPage != "") {
		return errors.New("custom_page is required only with page: custom")
	}
	return nil
}

// Preserve omission defaults while rejecting an explicitly invalid status 0.
func (b *BlockResponseConfig) UnmarshalYAML(unmarshal func(any) error) error {
	var raw struct {
		StatusCode *int   `yaml:"status_code"`
		Page       string `yaml:"page"`
		CustomPage string `yaml:"custom_page"`
	}
	if err := unmarshal(&raw); err != nil {
		return err
	}
	if raw.StatusCode != nil {
		if *raw.StatusCode == 0 {
			return errors.New("status_code 0 is invalid")
		}
		b.StatusCode = *raw.StatusCode
	}
	b.Page, b.CustomPage = raw.Page, raw.CustomPage
	return nil
}
