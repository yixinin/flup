package cloudreve

import (
	"bytes"
	"context"
	"encoding/json"
	"flup/output"
	"flup/storage"
	"fmt"
	"io"
	"net/http"
	"path"
	"time"
)

// API客户端结构体
type API struct {
	policyID       string
	host           string
	username       string
	password       string
	accessToken    string
	refreshToken   string
	accessExpires  time.Time
	refreshExpires time.Time
	db             *storage.Database
}

func (a *API) GenerateURI(path string) string {
	return fmt.Sprintf("cloudreve://my/%s", path)
}

// NewCloudreveAPI 创建Cloudreve API客户端实例
func NewCloudreveAPI(host, policyID, username, password string, db *storage.Database) *API {
	return &API{
		host:     host,
		policyID: policyID,
		username: username,
		password: password,
		db:       db,
	}
}

// 登录请求结构体
type LoginReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// 登录响应结构体
type LoginResp struct {
	Code int `json:"code"`
	Data struct {
		AccessToken    string `json:"access_token"`
		RefreshToken   string `json:"refresh_token"`
		AccessExpires  string `json:"access_expires"`
		RefreshExpires string `json:"refresh_expires"`
	} `json:"data"`
}

// 刷新token响应结构体
type RefreshTokenResp struct {
	Code int `json:"code"`
	Data struct {
		AccessToken    string `json:"access_token"`
		RefreshToken   string `json:"refresh_token"`
		AccessExpires  string `json:"access_expires"`
		RefreshExpires string `json:"refresh_expires"`
	} `json:"data"`
}

// 登录并获取token
func (a *API) Login(ctx context.Context) error {
	url := fmt.Sprintf("%s/session/token", a.host)
	reqBody := LoginReq{
		Username: a.username,
		Password: a.password,
	}
	jsonReq, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonReq))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	res, err := client.Do(httpReq)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		return fmt.Errorf("login failed: %s, response: %s", res.Status, string(body))
	}

	var loginResp LoginResp
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}

	if err := json.Unmarshal(body, &loginResp); err != nil {
		return err
	}

	if loginResp.Code != 0 {
		return fmt.Errorf("login failed with code: %d", loginResp.Code)
	}

	// 解析过期时间
	accessExpires, err := time.Parse(time.RFC3339, loginResp.Data.AccessExpires)
	if err != nil {
		return fmt.Errorf("parse access expires failed: %v", err)
	}
	refreshExpires, err := time.Parse(time.RFC3339, loginResp.Data.RefreshExpires)
	if err != nil {
		return fmt.Errorf("parse refresh expires failed: %v", err)
	}

	a.accessToken = loginResp.Data.AccessToken
	a.refreshToken = loginResp.Data.RefreshToken
	a.accessExpires = accessExpires
	a.refreshExpires = refreshExpires

	// 存储token到Badger数据库
	if a.db != nil {
		if err := a.db.StoreAuthTokens(a.accessToken, a.refreshToken, a.accessExpires, a.refreshExpires); err != nil {
			return err
		}
	}

	return nil
}

// 刷新token请求结构体
type RefreshTokenReq struct {
	RefreshToken string `json:"refresh_token"`
}

// 刷新访问token
func (a *API) RefreshToken(ctx context.Context) error {
	url := fmt.Sprintf("%s/session/token/refresh", a.host)
	reqBody := RefreshTokenReq{
		RefreshToken: a.refreshToken,
	}
	jsonReq, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonReq))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	res, err := client.Do(httpReq)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		return fmt.Errorf("refresh token failed: %s, response: %s", res.Status, string(body))
	}

	var refreshResp RefreshTokenResp
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}

	if err := json.Unmarshal(body, &refreshResp); err != nil {
		return err
	}

	if refreshResp.Code != 0 {
		return fmt.Errorf("refresh token failed with code: %d", refreshResp.Code)
	}

	// 解析过期时间
	accessExpires, err := time.Parse(time.RFC3339, refreshResp.Data.AccessExpires)
	if err != nil {
		return fmt.Errorf("parse access expires failed: %v", err)
	}
	refreshExpires, err := time.Parse(time.RFC3339, refreshResp.Data.RefreshExpires)
	if err != nil {
		return fmt.Errorf("parse refresh expires failed: %v", err)
	}

	a.accessToken = refreshResp.Data.AccessToken
	a.refreshToken = refreshResp.Data.RefreshToken
	a.accessExpires = accessExpires
	a.refreshExpires = refreshExpires

	// 更新Badger数据库中的token
	if a.db != nil {
		if err := a.db.StoreAuthTokens(a.accessToken, a.refreshToken, a.accessExpires, a.refreshExpires); err != nil {
			return err
		}
	}

	return nil
}

type CreateUploadSessionReq struct {
	LastModified int64  `json:"last_modified"`
	MimeType     string `json:"mime_type"`
	PolicyID     string `json:"policy_id"`
	Size         int64  `json:"size"`
	Uri          string `json:"uri"`
}

type CreateUploadSessionAck struct {
	UploadID       string `json:"upload_id"`
	ChunkSize      int    `json:"chunk_size"`
	CallbackSecret string `json:"callback_secret"`
	Endpoint       string `json:"endpoint"`
	Expires        int64  `json:"expires"`
	SessionID      int64  `json:"session_id"`
	Uri            string `json:"uri"`
	StoragePolicy  struct {
		MaxSize int64 `json:"max_size"`
	} `json:"storage_policy"`
}

// 初始化文件上传
func (a *API) InitUpload(ctx context.Context, filename string, size int64) (CreateUploadSessionAck, error) {
	// 检查token是否存在，不存在则登录
	if a.accessToken == "" {
		if err := a.Login(ctx); err != nil {
			return CreateUploadSessionAck{}, err
		}
	}

	var ack CreateUploadSessionAck
	url := fmt.Sprintf("%s/file/upload", a.host)
	var req = CreateUploadSessionReq{
		LastModified: time.Now().Unix(),
		Size:         size,
		PolicyID:     a.policyID,
		MimeType:     "application/octet-stream",
		Uri:          fmt.Sprintf("cloudreve://my/%s", filename),
	}
	jsonReq, err := json.Marshal(req)
	if err != nil {
		return ack, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, "PUT", url, bytes.NewBuffer(jsonReq))
	if err != nil {
		return ack, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", a.accessToken))

	client := &http.Client{}
	res, err := client.Do(httpReq)
	if err != nil {
		return ack, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		return ack, fmt.Errorf("init upload failed: %s, response: %s", res.Status, string(body))
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return ack, err
	}

	if err := json.Unmarshal(body, &ack); err != nil {
		return ack, err
	}

	return ack, nil
}

// 取消文件上传
func (a *API) CancelUpload(ctx context.Context) error {
	if err := a.ensureValidToken(ctx); err != nil {
		return err
	}

	url := fmt.Sprintf("%s/file/upload", a.host)

	req, err := http.NewRequestWithContext(ctx, "DELETE", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", a.accessToken))

	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to cancel upload: %s", res.Status)
	}

	return nil
}

// 存储策略响应
type GetPoliciesResp struct {
	Policies []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"policies"`
}

// 获取存储策略
func (a *API) GetPolicies(ctx context.Context) (GetPoliciesResp, error) {
	if err := a.ensureValidToken(ctx); err != nil {
		return GetPoliciesResp{}, err
	}

	var resp GetPoliciesResp
	url := fmt.Sprintf("%s/user/setting/policies", a.host)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return resp, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", a.accessToken))

	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return resp, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return resp, fmt.Errorf("failed to get policies: %s", res.Status)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return resp, err
	}

	if err := json.Unmarshal(body, &resp); err != nil {
		return resp, err
	}

	return resp, nil
}

// 文件列表响应
type GetFileListResp struct {
	Files []output.FileInfo `json:"files"`
}

// 获取文件列表
func (a *API) GetFileList(ctx context.Context, dir, name string) (GetFileListResp, error) {
	if err := a.ensureValidToken(ctx); err != nil {
		return GetFileListResp{}, err
	}

	var resp GetFileListResp
	var uri = "cloudreve://my/"
	if dir != "" {
		uri = path.Join(uri, dir)
	}
	if name != "" {
		uri = fmt.Sprintf("%s?name=%s", uri, name)
	}
	url := fmt.Sprintf("%s/file?uri=%s", a.host, uri)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return resp, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", a.accessToken))

	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return resp, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		return resp, fmt.Errorf("failed to get file list: %s, response: %s", res.Status, string(body))
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return resp, err
	}

	if err := json.Unmarshal(body, &resp); err != nil {
		return resp, err
	}

	return resp, nil
}

// 上传文件块
func (a *API) UploadChunk(ctx context.Context, sessionID string, index int, data []byte) error {
	if err := a.ensureValidToken(ctx); err != nil {
		return err
	}

	url := fmt.Sprintf("%s/file/upload/%s/%d", a.host, sessionID, index)

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", a.accessToken))

	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		return fmt.Errorf("upload chunk failed: %s, response: %s", res.Status, string(body))
	}

	return nil
}

// 文件信息响应
func (a *API) GetFileInfo(ctx context.Context, path string) (output.FileInfo, error) {
	var fileInfo output.FileInfo
	uri := fmt.Sprintf("cloudreve://my/%s", path)
	url := fmt.Sprintf("%s/file/info?uri=%s", a.host, uri)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fileInfo, err
	}

	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return fileInfo, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		return fileInfo, fmt.Errorf("failed to get file info: %s, response: %s", res.Status, string(body))
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return fileInfo, err
	}

	if err := json.Unmarshal(body, &fileInfo); err != nil {
		return fileInfo, err
	}

	return fileInfo, nil
}

// 删除文件
func (a *API) DeleteFile(ctx context.Context, path string) error {
	if err := a.ensureValidToken(ctx); err != nil {
		return err
	}

	uri := fmt.Sprintf("cloudreve://my/%s", path)
	url := fmt.Sprintf("%s/file?uri=%s", a.host, uri)

	req, err := http.NewRequestWithContext(ctx, "DELETE", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", a.accessToken))

	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		return fmt.Errorf("failed to delete file: %s, response: %s", res.Status, string(body))
	}

	return nil
}

// 获取文件下载链接
func (a *API) GetFileDownloadURL(ctx context.Context, path string) (string, error) {
	if err := a.ensureValidToken(ctx); err != nil {
		return "", err
	}

	uri := fmt.Sprintf("cloudreve://my/%s", path)
	url := fmt.Sprintf("%s/file/url?uri=%s", a.host, uri)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", a.accessToken))

	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		return "", fmt.Errorf("failed to get download url: %s, response: %s", res.Status, string(body))
	}

	var resp struct {
		URL string `json:"url"`
	}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return "", err
	}

	if err := json.Unmarshal(body, &resp); err != nil {
		return "", err
	}

	return resp.URL, nil
}

// 确保token有效
func (a *API) ensureValidToken(ctx context.Context) error {
	// 如果没有token，尝试从数据库加载
	if a.accessToken == "" && a.db != nil {
		accessToken, refreshToken, accessExpires, refreshExpires, err := a.db.GetAuthTokens()
		if err == nil {
			a.accessToken = accessToken
			a.refreshToken = refreshToken
			a.accessExpires = accessExpires
			a.refreshExpires = refreshExpires
		}
	}

	// 检查access token是否过期
	if time.Now().After(a.accessExpires) {
		// 尝试刷新token
		if err := a.RefreshToken(ctx); err != nil {
			// 刷新失败，重新登录
			return a.Login(ctx)
		}
	} else if a.accessToken == "" {
		// 没有token且数据库中也没有，直接登录
		return a.Login(ctx)
	}

	return nil
}

// 创建文件请求结构体
type CreateFileReq struct {
	Uri           string `json:"uri"`
	Type          string `json:"type"`
	ErrOnConflict bool   `json:"err_on_conflict,omitempty"`
}

// 创建文件/目录响应结构体
type CreateFileResp struct {
	Code int `json:"code"`
	Data struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		IsDir     bool   `json:"is_dir"`
		Path      string `json:"path"`
		CreatedAt string `json:"created_at"`
	} `json:"data"`
}

// 创建文件或目录
func (a *API) createFile(ctx context.Context, path string, isDir bool) error {
	if err := a.ensureValidToken(ctx); err != nil {
		return err
	}

	url := fmt.Sprintf("%s/file/create", a.host)
	reqBody := CreateFileReq{
		Uri:           a.GenerateURI(path),
		Type:          map[bool]string{true: "folder", false: "file"}[isDir],
		ErrOnConflict: true,
	}

	jsonReq, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonReq))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", a.accessToken))

	client := &http.Client{}
	res, err := client.Do(httpReq)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		return fmt.Errorf("create %s failed: %s, response: %s", map[bool]string{true: "directory", false: "file"}[isDir], res.Status, string(body))
	}

	var createResp CreateFileResp
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}

	if err := json.Unmarshal(body, &createResp); err != nil {
		return err
	}

	if createResp.Code != 0 {
		return fmt.Errorf("create %s failed with code: %d", map[bool]string{true: "directory", false: "file"}[isDir], createResp.Code)
	}

	return nil
}

// BackendStorage接口实现
func (a *API) CreateFile(ctx context.Context, path string) error {
	return a.createFile(ctx, path, false)
}

func (a *API) CreateDir(ctx context.Context, path string) error {
	return a.createFile(ctx, path, true)
}
