package config

type Config struct {
	Backend Backend `json:"backend"`
}

type Backend struct {
	Host     string `json:"host"`
	PolicyID string `json:"policy_id"`
	Username string `json:"username"`
	Password string `json:"password"`
}