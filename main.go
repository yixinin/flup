package main

import (
	"flup/input/smb"
	"flup/output/cloudreve"
	"flup/storage"
	"log"
)

func main() {

	// 初始化数据库
	database, err := storage.NewDatabase("data_dir")
	if err != nil {
		log.Fatalf("初始化数据库失败: %v", err)
	}
	defer database.Close()
	var apiHost = "https://drive4.iakl.top"
	var policyID = "3xtq"
	var username = "yixinin@outlook.com"
	var password = ""
	var storage = cloudreve.NewCloudreveBackend(apiHost, policyID, username, password, database)
	smb.StartSmb(database, storage)

}
