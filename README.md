### ZIP

参考：
fork: https://github.com/alexmullins/zip

zip 加密多个文件 加密算法支持： 
- 标准加密
- AES


注意

Zip 标准加密实际上并不安全。除非您必须使用它，否则请改用 AES 加密。



#### 例子

```golang
package main

import (
	"errors"
	"fmt"
	"git.s/zhangjie/zip"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

func main() {
	// 压缩 zip 文件
	outFilename := "./test.zip"                                     // 输出文件
	zipFiles := []string{"/tmp/test.html", "/tmp/test.py"}          // 需要压缩的文件
	password := "123"                                               // 加密密码
	encryptionMethod := zip.StandardEncryption                      // 加密算法
	//encryptionMethod := zip.AES256Encryption

	err := ZipFilesEncrypt(outFilename, zipFiles, password, encryptionMethod)
	if err != nil {
		fmt.Println("zip Err:", err)
		return
	}

	// 解压缩
	zipFile := "/tmp/test.zip"  // 需要 解压缩 zip 文件
	outDir := "/tmp/test"      //  解压缩 输出目录
	if err = UnzipDecrypt(zipFile, outDir, password, encryptionMethod); err != nil {
		fmt.Println("un zip Err:", err)
		return
	}
}

// from https://golangcode.com/create-zip-files-in-go/

// ZipFilesEncrypt compresses one or many files into a single zip archive file.
// Param 1: filename is the output zip file's name.
// Param 2: files is a list of files to add to the zip.
// Param 3: zip passowrd.
// Param 4: zip Encryption Method
func ZipFilesEncrypt(filename string, files []string, password string, enc zip.EncryptionMethod) error {

	newZipFile, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer newZipFile.Close()

	zipWriter := zip.NewWriter(newZipFile)
	defer func(zipWriter *zip.Writer) { _ = zipWriter.Close() }(zipWriter)

	// Add files to zip
	for _, file := range files {
		if err = AddFileToZipEncrypt(zipWriter, file, password, enc); err != nil {
			return err
		}
	}
	return nil
}

func AddFileToZipEncrypt(zipWriter *zip.Writer, filename, password string, enc zip.EncryptionMethod) error {

	fileToZip, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer func(fileToZip *os.File) { _ = fileToZip.Close() }(fileToZip)

	// Get the file information
	info, err := fileToZip.Stat()
	if err != nil {
		return err
	}

	header, err := zip.FileInfoHeader(info)
	if err != nil {
		return err
	}

	// Using FileInfoHeader() above only uses the basename of the file. If we want
	// to preserve the folder structure we can overwrite this with the full path.
	header.Name = filepath.Base(filename)

	// Change to deflate to gain better compression
	// see http://golang.org/pkg/archive/zip/#pkg-constants
	header.Method = zip.Deflate
	header.SetPassword(password)
	header.SetEncryptionMethod(enc)

	writer, err := zipWriter.CreateHeader(header)

	_, _ = writer.Write([]byte("\xEF\xBB\xBF"))
	if err != nil {
		return err
	}
	_, err = io.Copy(writer, fileToZip)
	return err
}

func UnzipDecrypt(zipFile, dstDir, password string, enc zip.EncryptionMethod) error {
	r, err := zip.OpenReader(zipFile)
	if err != nil {
		return err
	}
	defer func(r *zip.ReadCloser) { _ = r.Close() }(r)

	for _, f := range r.File {
		if f.IsEncrypted() {
			f.SetPassword(password)
			f.SetEncryptionMethod(enc)
		} else {
			return errors.New("zip没有被加密，无法导入")
		}
		err = extractFile(f, dstDir)
		if err != nil {
			return err
		}
	}
	return nil
}

// from https://stackoverflow.com/questions/20357223/easy-way-to-unzip-file-with-golang
func extractFile(f *zip.File, dest string) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer func(rc io.ReadCloser) { _ = rc.Close() }(rc)

	dstFile := path.Join(dest, f.Name)
	// Check for ZipSlip (Directory traversal)
	if !strings.HasPrefix(dstFile, filepath.Clean(dest)+string(os.PathSeparator)) {
		return fmt.Errorf("illegal file path: %s", dstFile)
	}

	if f.FileInfo().IsDir() {
		err = os.MkdirAll(dstFile, f.Mode())
		if err != nil {
			return err
		}

	} else {
		err = os.MkdirAll(filepath.Dir(dstFile), f.Mode())
		if err != nil {
			return err
		}

		err = SaveFile(rc, dstFile)
		if err != nil {
			return err
		}
	}
	return nil
}

func SaveFile(src io.Reader, dstFile string) error {

	t, err := os.OpenFile(dstFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return errors.New(fmt.Sprintf("failed to upload package :%v", err))
	}
	defer func() { _ = t.Close() }()

	_, err = io.Copy(t, src)
	return err
}

```
