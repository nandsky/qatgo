package keystore

import (
	"gopkg.in/ini.v1"
	"os"
)

type KeyPair struct {
	//
	Sni string
	//
	KeyFile string
	//
	CertFile string
}

var GKeyStore map[string]KeyPair

func LoadKeyStore(filename string) (map[string]KeyPair, error) {

	ret := make(map[string]KeyPair, 0)
	cf, err := ini.Load(filename)
	if err != nil {
		return ret, err
	}
	sections := cf.Sections()

readSection:
	for _, section := range sections {
		certFile := section.Key("cert").String()
		keyFile := section.Key("key").String()

		if !fileExist(certFile) {
			continue readSection
		}
		if !fileExist(keyFile) {
			continue readSection
		}

		//cy.LoadX509KeyPair(certFile, keyFile)
		ret[section.Name()] = KeyPair{
			CertFile: certFile,
			KeyFile:  keyFile,
		}

	}
	GKeyStore = ret
	return ret, nil
}

func GetKeyPair(sni string) KeyPair {

	return GKeyStore[sni]
}

func fileExist(fileName string) bool {
	if _, err := os.Stat(fileName); err == nil {
		return true
	}
	return false
}
