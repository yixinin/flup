package smb

import (
	"flup/output"
	"flup/storage"
	"fmt"
	"net"
)

// 启动SMB服务器
func (s *SMBServer) Start(addr string) error {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer listener.Close()

	fmt.Printf("SMB1.0 Server listening on %s\n", addr)

	fmt.Printf("NetBIOS name: %s\n", s.NetBIOSName)

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Printf("Accept error: %v\n", err)
			continue
		}

		fmt.Printf("New connection from %s\n", conn.RemoteAddr().String())
		go s.handleConnection(conn)
	}
}

func StartSmb(db *storage.Database, storage output.BackendStorage) {
	// 配置服务器参数
	netbiosName := "GOSMBSERVER"
	listenAddr := ":445"

	// 创建服务器实例
	server := NewSMBServer(netbiosName, db, storage)

	// 启动UDP服务器
	if err := server.StartUDPServers(); err != nil {
		fmt.Printf("启动UDP服务器失败: %v\n", err)
	}

	// 启动服务器
	if err := server.Start(listenAddr); err != nil {
		fmt.Printf("Server error: %v\n", err)
	}
}
