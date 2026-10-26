package lib

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

func validateKeyName(name string) error {
	if name == "" || strings.HasPrefix(name, ".") || !filepath.IsLocal(name) || strings.ContainsAny(name, `/\:`) {
		return errors.New("invalid key name")
	}
	return nil
}

func validateItemName(name string) error {
	if !filepath.IsLocal(name) || name == "." || strings.ContainsAny(name, `\:`) {
		return errors.New("invalid password path")
	}
	for _, part := range strings.Split(filepath.ToSlash(name), "/") {
		if part == ".." {
			return errors.New("invalid password path")
		}
	}
	return nil
}

// os.Root is needed here: go/file has no descriptor-relative containment or
// exclusive-create API. Keep each store confined even during symlink changes.
func openStore(kind, keyName string, create bool) (*os.Root, error) {
	if keyName != "" || kind == "passwords" {
		if err := validateKeyName(keyName); err != nil {
			return nil, err
		}
	}
	if create {
		if err := EnsureDir(GetKeysRootPath()); err != nil {
			return nil, err
		}
	}
	root, err := os.OpenRoot(GetKeysRootPath())
	if err != nil {
		return nil, err
	}
	defer root.Close()
	if create {
		if err := root.MkdirAll(kind, 0700); err != nil {
			return nil, err
		}
	}
	store, err := root.OpenRoot(kind)
	if err != nil {
		return nil, err
	}
	if keyName == "" {
		return store, nil
	}
	defer store.Close()
	if create {
		if err := store.MkdirAll(keyName, 0700); err != nil {
			return nil, err
		}
	}
	return store.OpenRoot(keyName)
}

func writeSecret(root *os.Root, name string, data []byte, exclusive bool) error {
	flags := os.O_WRONLY | os.O_CREATE
	if exclusive {
		flags |= os.O_EXCL
	} // Creation must never replace an existing key.
	f, err := root.OpenFile(name, flags, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("secret must be a regular file")
	}
	if err := f.Chmod(0600); err != nil {
		return err
	}
	if err := f.Truncate(0); err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	return f.Close()
}

// RemoveKeystore removes a named key without escaping the keystore directory.
func RemoveKeystore(name string) error {
	if err := validateKeyName(name); err != nil {
		return err
	}
	if name == "default" {
		return errors.New("cannot remove the built-in key")
	}
	root, err := openStore("keystore", "", false)
	if err != nil {
		return err
	}
	defer root.Close()
	return root.Remove(name)
}

func listPasswordFiles(root *os.Root) ([]string, error) {
	var names []string
	err := fs.WalkDir(root.FS(), ".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("symbolic links are not password items")
		}
		if !entry.IsDir() {
			names = append(names, filepath.FromSlash(path))
		}
		return nil
	})
	return names, err
}
