package sni

import (
	"log"
	"net"
)

func PeekSNI(conn net.Conn) (string, net.Conn, error) {
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return "", nil, err
	}
	serverName, err := SniStream(buf[:n])
	if err != nil {
		log.Println("[SNI] error on found the with TLS servername", err)
		serverName, err = ExtractHostFromStream(buf[:n])
		if err != nil {
			log.Println("[SNI] error on found the servername", err)
		}
	}

	log.Printf("found the server name domain: %s", serverName)

	if err != nil {
		return "", nil, err
	}
	return serverName, &ConnBuffer{buf: buf[:n], conn: conn}, nil
}
