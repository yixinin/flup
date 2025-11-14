package storage

import (
	"encoding/binary"
	"fmt"
	"path/filepath"
	"time"

	"github.com/dgraph-io/badger/v4"
)

// Database 基于Badger的SMB数据存储引擎
type Database struct {
	db *badger.DB
}

// NewDatabase 创建新的数据库实例
func NewDatabase(dataDir string) (*Database, error) {
	opts := badger.DefaultOptions(dataDir)
	// 配置Badger选项
	opts.Dir = filepath.Join(dataDir, "badger_data")
	opts.ValueDir = filepath.Join(dataDir, "badger_value")

	// 打开数据库
	db, err := badger.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("无法打开Badger数据库: %v", err)
	}

	return &Database{db: db}, nil
}

// Close 关闭数据库连接
func (d *Database) Close() error {
	if d.db != nil {
		return d.db.Close()
	}
	return nil
}

// GenerateFID 生成唯一的FID
func (d *Database) GenerateFID() (uint16, error) {
	var fid uint16

	err := d.db.Update(func(txn *badger.Txn) error {
		// 获取当前计数器
		key := []byte("fid_counter")
		item, err := txn.Get(key)

		if err == badger.ErrKeyNotFound {
			// 首次使用，从1开始
			fid = 1
		} else if err != nil {
			return fmt.Errorf("获取计数器失败: %v", err)
		} else {
			// 读取当前值并递增
			err := item.Value(func(val []byte) error {
				if len(val) != 2 {
					return fmt.Errorf("无效的计数器值长度")
				}
				fid = binary.BigEndian.Uint16(val)
				fid++
				// 处理溢出，回到1
				if fid == 0 {
					fid = 1
				}
				return nil
			})
			if err != nil {
				return err
			}
		}

		// 保存新计数器值
		val := make([]byte, 2)
		binary.BigEndian.PutUint16(val, fid)
		return txn.Set(key, val)
	})

	return fid, err
}

// StoreFIDMapping 存储FID与文件名的映射关系
func (d *Database) StoreFIDMapping(fid uint16, filename string) error {
	return d.db.Update(func(txn *badger.Txn) error {
		// FID -> 文件名映射
		fidKey := []byte(fmt.Sprintf("fid:%d", fid))
		if err := txn.Set(fidKey, []byte(filename)); err != nil {
			return fmt.Errorf("存储FID映射失败: %v", err)
		}

		// 文件名 -> FID反向映射
		nameKey := []byte(fmt.Sprintf("name:%s", filename))
		fidVal := make([]byte, 2)
		binary.BigEndian.PutUint16(fidVal, fid)
		if err := txn.Set(nameKey, fidVal); err != nil {
			return fmt.Errorf("存储文件名映射失败: %v", err)
		}

		return nil
	})
}

// GetFilenameByFID 根据FID获取文件名
func (d *Database) GetFilenameByFID(fid uint16) (string, error) {
	var filename string

	err := d.db.View(func(txn *badger.Txn) error {
		key := []byte(fmt.Sprintf("fid:%d", fid))
		item, err := txn.Get(key)
		if err == badger.ErrKeyNotFound {
			return fmt.Errorf("FID不存在: %d", fid)
		} else if err != nil {
			return fmt.Errorf("获取文件名失败: %v", err)
		}

		return item.Value(func(val []byte) error {
			filename = string(val)
			return nil
		})
	})

	return filename, err
}

// GetFIDByFilename 根据文件名获取FID
func (d *Database) GetFIDByFilename(filename string) (uint16, error) {
	var fid uint16

	err := d.db.View(func(txn *badger.Txn) error {
		key := []byte(fmt.Sprintf("name:%s", filename))
		item, err := txn.Get(key)
		if err == badger.ErrKeyNotFound {
			return fmt.Errorf("文件不存在: %s", filename)
		} else if err != nil {
			return fmt.Errorf("获取FID失败: %v", err)
		}

		return item.Value(func(val []byte) error {
			if len(val) != 2 {
				return fmt.Errorf("无效的FID值长度")
			}
			fid = binary.BigEndian.Uint16(val)
			return nil
		})
	})

	return fid, err
}

// DeleteFIDMapping 删除FID与文件名的映射关系
func (d *Database) DeleteFIDMapping(fid uint16, filename string) error {
	return d.db.Update(func(txn *badger.Txn) error {
		// 删除FID -> 文件名映射
		fidKey := []byte(fmt.Sprintf("fid:%d", fid))
		if err := txn.Delete(fidKey); err != nil {
			return fmt.Errorf("删除FID映射失败: %v", err)
		}

		// 删除文件名 -> FID反向映射
		nameKey := []byte(fmt.Sprintf("name:%s", filename))
		if err := txn.Delete(nameKey); err != nil {
			return fmt.Errorf("删除文件名映射失败: %v", err)
		}

		return nil
	})
}

// 存储认证令牌
func (d *Database) StoreAuthTokens(accessToken, refreshToken string, accessExpires, refreshExpires time.Time) error {
	return d.db.Update(func(txn *badger.Txn) error {
		// 存储access token
		if err := txn.Set([]byte("auth:access_token"), []byte(accessToken)); err != nil {
			return fmt.Errorf("存储access token失败: %v", err)
		}

		// 存储refresh token
		if err := txn.Set([]byte("auth:refresh_token"), []byte(refreshToken)); err != nil {
			return fmt.Errorf("存储refresh token失败: %v", err)
		}

		// 存储access token过期时间
		accessExpiresBytes, err := accessExpires.MarshalBinary()
		if err != nil {
			return fmt.Errorf("序列化access过期时间失败: %v", err)
		}
		if err := txn.Set([]byte("auth:access_expires"), accessExpiresBytes); err != nil {
			return fmt.Errorf("存储access过期时间失败: %v", err)
		}

		// 存储refresh token过期时间
		refreshExpiresBytes, err := refreshExpires.MarshalBinary()
		if err != nil {
			return fmt.Errorf("序列化refresh过期时间失败: %v", err)
		}
		if err := txn.Set([]byte("auth:refresh_expires"), refreshExpiresBytes); err != nil {
			return fmt.Errorf("存储refresh过期时间失败: %v", err)
		}

		return nil
	})
}

// 获取认证令牌
func (d *Database) GetAuthTokens() (accessToken, refreshToken string, accessExpires, refreshExpires time.Time, err error) {
	err = d.db.View(func(txn *badger.Txn) error {
		// 获取access token
		item, err := txn.Get([]byte("auth:access_token"))
		if err != nil {
			return fmt.Errorf("获取access token失败: %v", err)
		}
		err = item.Value(func(val []byte) error {
			accessToken = string(val)
			return nil
		})
		if err != nil {
			return err
		}

		// 获取refresh token
		item, err = txn.Get([]byte("auth:refresh_token"))
		if err != nil {
			return fmt.Errorf("获取refresh token失败: %v", err)
		}
		err = item.Value(func(val []byte) error {
			refreshToken = string(val)
			return nil
		})
		if err != nil {
			return err
		}

		// 获取access token过期时间
		item, err = txn.Get([]byte("auth:access_expires"))
		if err != nil {
			return fmt.Errorf("获取access过期时间失败: %v", err)
		}
		err = item.Value(func(val []byte) error {
			return accessExpires.UnmarshalBinary(val)
		})
		if err != nil {
			return err
		}

		// 获取refresh token过期时间
		item, err = txn.Get([]byte("auth:refresh_expires"))
		if err != nil {
			return fmt.Errorf("获取refresh过期时间失败: %v", err)
		}
		err = item.Value(func(val []byte) error {
			return refreshExpires.UnmarshalBinary(val)
		})
		if err != nil {
			return err
		}

		return nil
	})

	return accessToken, refreshToken, accessExpires, refreshExpires, err
}
