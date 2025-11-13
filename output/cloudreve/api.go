package cloudreve

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

type api struct {
	host string
}

type CreateUploadSessionReq struct {
	LastModified int64  `json:"last_modified"`
	MimeType     string `json:"mime_type"`
	PolicyID     string `json:"policy_id"`
	Size         int64  `json:"size"`
	Uri          string `json:"uri"`
}

type CreateUploadSessionAck struct {
	CallbackSecret string `json:"callback_secret"`
	ChunkSize      int64  `json:"chunk_size"`
	Expires        int64  `json:"expires"`
	SessionID      int64  `json:"session_id"`
	Uri            string `json:"uri"`
	StoragePolicy  struct {
		MaxSize int64 `json:"max_size"`
	} `json:"storage_policy"`
}

// 初始化文件上传 - 修复API路径
func (a *api) InitUpload(ctx context.Context, req *CreateUploadSessionReq) (CreateUploadSessionAck, error) {
	var ack CreateUploadSessionAck
	url := fmt.Sprintf("%s/file/upload", a.host) // 移除/api/v4前缀

	jsonReq, err := json.Marshal(req)
	if err != nil {
		return ack, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, "PUT", url, bytes.NewBuffer(jsonReq))
	if err != nil {
		return ack, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	res, err := client.Do(httpReq)
	if err != nil {
		return ack, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(res.Body)
		return ack, fmt.Errorf("init upload failed: %s, response: %s", res.Status, string(body))
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return ack, err
	}

	if err := json.Unmarshal(body, &ack); err != nil {
		return ack, err
	}

	return ack, nil
}

// 取消文件上传
func (a *api) CancelUpload(ctx context.Context) error {
	url := fmt.Sprintf("%s%s", a.host, "/file/upload")

	req, err := http.NewRequestWithContext(ctx, "DELETE", url, nil)
	if err != nil {
		return err
	}

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

// 文件信息结构体
type FileInfo struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Size      int64  `json:"size"`
	CreatedAt string `json:"created_at"`
}

// 文件列表响应
type GetFileListResp struct {
	Files []FileInfo `json:"files"`
}

// 获取存储策略
func (a *api) GetPolicies(ctx context.Context) (GetPoliciesResp, error) {
	var resp GetPoliciesResp
	url := fmt.Sprintf("%s/user/setting/policies", a.host)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return resp, err
	}

	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return resp, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return resp, fmt.Errorf("failed to get policies: %s", res.Status)
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return resp, err
	}

	if err := json.Unmarshal(body, &resp); err != nil {
		return resp, err
	}

	return resp, nil
}

// 获取文件列表
func (a *api) GetFileList(ctx context.Context) (GetFileListResp, error) {
	var resp GetFileListResp
	url := fmt.Sprintf("%s/file", a.host)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return resp, err
	}

	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return resp, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(res.Body)
		return resp, fmt.Errorf("failed to get file list: %s, response: %s", res.Status, string(body))
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return resp, err
	}

	if err := json.Unmarshal(body, &resp); err != nil {
		return resp, err
	}

	return resp, nil
}

// 上传文件块
func (a *api) UploadChunk(ctx context.Context, sessionID string, index int, data []byte) error {
	url := fmt.Sprintf("%s/file/upload/%s/%d", a.host, sessionID, index)

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(res.Body)
		return fmt.Errorf("upload chunk failed: %s, response: %s", res.Status, string(body))
	}

	return nil
}
