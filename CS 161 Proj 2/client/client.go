package client

// CS 161 Project 2

// Only the following imports are allowed! ANY additional imports
// may break the autograder!
// - bytes
// - encoding/hex
// - encoding/json
// - errors
// - fmt
// - github.com/cs161-staff/project2-userlib
// - github.com/google/uuid
// - strconv
// - strings

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	// "strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}










// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
type User struct {
	Username string
	HashedPW []byte
	Salt []byte
	Uuid uuid.UUID
	PKEDecKey userlib.PrivateKeyType
	DSSignKey userlib.PrivateKeyType
}

type File struct {
	Uuid uuid.UUID
	OwnerName string
	FileName string // Owner's filename
	Content []byte
	SenderToRecipient map[string][]string
}

type Info struct {
	Uuid_file []byte // 16 bytes, but don't forget to cast this to uuid.UUID before using as a uuid
	RootKey []byte // 16 bytes
	// SymKey []byte // 16 bytes
	// MacKey []byte // 16 bytes
	// MacVal []byte // 64 bytes
	// MacCounterVal []byte // 64 bytes - this is the Mac value of the counter
}










// NOTE: The following methods have toy (insecure!) implementations.

func EncThenMac(MacKey []byte, EncKey []byte, value []byte) (ciphertext []byte, mac []byte, err error) {
	ciphertext = userlib.SymEnc(EncKey, userlib.RandomBytes(16), value)
	mac, err = userlib.HMACEval(MacKey, ciphertext)
	if err != nil {
		return nil, nil, err
	}
	return ciphertext, mac, nil
}

func EncMacKeysFromRoot(RootKey []byte, EncPurpose string, MacPurpose string) (EncKey []byte, MacKey []byte, err error) {
	EncKey, err = userlib.HashKDF(RootKey, []byte(EncPurpose))
	if err != nil {
		return nil, nil, err
	}
	MacKey, err = userlib.HashKDF(RootKey, []byte(MacPurpose))
	if err != nil {
		return nil, nil, err
	}
	return EncKey[:16], MacKey[:16], nil
}

func indexOf(arr []string, val string) int {
	n := len(arr)
	var i int
	for i = 0; i < n; i++ {
		if arr[i] == val {
			return i
		}
	}
	return -1
}

func remove(arr []string, i int) []string {
	return append(arr[:i], arr[i + 1:]...)
}


func compare(arr1 []byte, arr2 []byte) bool {
	a := len(arr1)
	if a == len(arr2) {
		for i := 0; i < a; i++ {
			if arr1[i] != arr2[i] {
				return false
			}
		}
	} else {
		return false
	}
	return true
}





func InitUser(username string, password string) (userdataptr *User, err error) {
	if len(username) == 0 {
		return nil, errors.New("received empty username")
	}
	uuid_user, err := uuid.FromBytes(userlib.Hash([]byte(username))[:16])
	if err != nil {
		return nil, err
	}
	_, ok := userlib.DatastoreGet(uuid_user)
	if ok {
		return nil, errors.New("repeated username")
	}
	var userdata User
	userdata.Uuid = uuid_user
	userdata.Username = username

	marshal, err := json.Marshal(username + "0" + password)
	if err != nil {
		return nil, err
	}
	userdata.Salt = userlib.Hash(marshal)[:16]
	userdata.HashedPW = userlib.Argon2Key([]byte(password), userdata.Salt, 16) // might need to change to
	// 16 or 32 bits instead
	PKEEncKey, PKEDecKey, err := userlib.PKEKeyGen()
	if err != nil {
		return nil, err
	}
	userdata.PKEDecKey = PKEDecKey
	DSSignKey, DSVerifyKey, err := userlib.DSKeyGen()
	if err != nil {
		return nil, err
	}
	userdata.DSSignKey = DSSignKey
	err = userlib.KeystoreSet(username + "pke", PKEEncKey)
	if err != nil {
		return nil, err
	}
	err = userlib.KeystoreSet(username + "ds", DSVerifyKey)
	if err != nil {
		return nil, err
	}

	EncKey, MacKey, err := EncMacKeysFromRoot(userdata.HashedPW, "enc", "mac")
	if err != nil {
		return nil, err
	}
	marshal, err = json.Marshal(userdata)
	if err != nil {
		return nil, err
	}
	ciphertext, mac, err := EncThenMac(MacKey, EncKey, marshal)
	if err != nil {
		return nil, err
	}
	userlib.DatastoreSet(userdata.Uuid, ciphertext)
	uuid_MAC, err := uuid.FromBytes(userlib.Hash([]byte(username + "MAC"))[:16])
	if err != nil {
		return nil, err
	}
	userlib.DatastoreSet(uuid_MAC, mac)
	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata
	marshal, err := json.Marshal(username + "0" + password)
	if err != nil {
		return nil, err
	}
	Salt := userlib.Hash(marshal)[:16]
	uuid_user, err := uuid.FromBytes(userlib.Hash([]byte(username))[:16])
	if err != nil {
		return nil, err
	}
	EncUser, ok := userlib.DatastoreGet(uuid_user) // if there is no user with this username then it this
	// will error
	if !ok {
		return nil, err
	}
	HashedPW := userlib.Argon2Key([]byte(password), Salt, 16)
	EncKey, MacKey, err := EncMacKeysFromRoot(HashedPW, "enc", "mac")
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(userlib.SymDec(EncKey, EncUser), &userdata)
	if err != nil {
		return nil, err
	}
	if !userlib.HMACEqual(userdata.HashedPW, HashedPW) {
		return nil, errors.New("wrong username or password")
	}
	mac, err := userlib.HMACEval(MacKey, EncUser)
	if err != nil {
		return nil, err
	}
	uuid_MAC, err := uuid.FromBytes(userlib.Hash([]byte(username + "MAC"))[:16])
	if err != nil {
		return nil, err
	}
	MAC, ok := userlib.DatastoreGet(uuid_MAC)
	if !ok {
		return nil, errors.New("can't find the mac")
	}
	if !userlib.HMACEqual(MAC, mac) {
		return nil, errors.New("malicious action")
	}
	return userdataptr, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	uuid_stuff, err := uuid.FromBytes(userlib.Hash(append(userlib.Hash([]byte(userdata.Username)), userlib.Hash([]byte(filename))...))[:16])
	if err != nil {
		return err
	}
	info, ok := userlib.DatastoreGet(uuid_stuff) // this is the Enc(marshal(info)), so we need to decrypt then unmarshal
	if !ok { // not owner or file doesn't exist
		uuid_stuff_2, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "0" + filename))[:16]) // this maps to encrypted
		if err != nil {
			return err
		}
		// invPtr (encryped with the user's own public encryption key)
		invPtr_bytes, ok := userlib.DatastoreGet(uuid_stuff_2)
		if !ok { // file does not exist, need to create file object
		/* 
			*
			*
			*
			--- If file does not exist, make the new file ---
			*
			*
			*
		*/
			var file File

			file_uuid_bytes := userlib.RandomBytes(16)
			file.Uuid, err = uuid.FromBytes(file_uuid_bytes)
			if err != nil {
				return err
			}
			file.OwnerName = userdata.Username
			file.FileName = filename
			file.Content = content
			file.SenderToRecipient = make(map[string][]string)
			file.SenderToRecipient[userdata.Username] = []string{}
			root_key := userlib.RandomBytes(16)
			enc_key, mac_key, err := EncMacKeysFromRoot(root_key, "enc", "mac")
			if err != nil {
				return err
			}

			// CTFI = Children_To_Filename_invPtr
			CTFI_uuid_bytes, err := userlib.HashKDF(file_uuid_bytes, []byte("children map"))
			if err != nil {
				return err
			}
			CTFI_MAC_uuid_bytes, err := userlib.HashKDF(CTFI_uuid_bytes[:16], []byte("mac"))
			if err != nil {
				return err
			}
			CTFI_uuid, err := uuid.FromBytes(CTFI_uuid_bytes[:16])
			if err != nil {
				return err
			}
			CTFI_MAC_uuid, err := uuid.FromBytes(CTFI_MAC_uuid_bytes[:16])
			if err != nil {
				return err
			}
			
			CTFI := make(map[string][2]string)
			marshal_CTFI, err := json.Marshal(CTFI)
			if err != nil {
				return err
			}
			enc_marshal_CTFI, CTFI_MAC_val, err := EncThenMac(mac_key, enc_key, marshal_CTFI)
			if err != nil {
				return err
			}
			userlib.DatastoreSet(CTFI_uuid, enc_marshal_CTFI)
			userlib.DatastoreSet(CTFI_MAC_uuid, CTFI_MAC_val)

			marshal_file, err := json.Marshal(file)
			if err != nil {
				return err
			}
			enc_marshal_file, mac_val, err := EncThenMac(mac_key, enc_key, marshal_file)
			if err != nil {
				return err
			}
			userlib.DatastoreSet(file.Uuid, enc_marshal_file)
			// MAC_uuid_bytes, err := userlib.HashKDF(file_uuid_bytes, []byte("mac"))
			// MAC_uuid, err := uuid.FromBytes(MAC_uuid_bytes[:16])
			// userlib.DatastoreSet(MAC_uuid, mac_val)


			// setting counter for the new file to 0 and creating the mapping for the MAC of the counter
			marshal_zero, err := json.Marshal(0)
			if err != nil {
				return err
			}
			enc_counter, mac_counter, err := EncThenMac(mac_key, enc_key, marshal_zero)
			if err != nil {
				return err
			}
			uuid_counter_bytes, err := userlib.HashKDF(file_uuid_bytes, []byte("counter"))
			if err != nil {
				return err
			}
			uuid_counter, err := uuid.FromBytes(uuid_counter_bytes[:16])
			if err != nil {
				return err
			}
			userlib.DatastoreSet(uuid_counter, enc_counter) // update the counter value for the file back to 0
			

			// creating and mapping info for the new file
			var info Info
			info.Uuid_file = file_uuid_bytes
			info.RootKey = root_key
			uuid_mac_val_bytes, err := userlib.HashKDF(file_uuid_bytes, []byte("mac val"))
			if err != nil {
				return err
			}
			uuid_mac_val, err := uuid.FromBytes(uuid_mac_val_bytes[:16])
			if err != nil {
				return err
			}
			uuid_mac_counter_val_bytes, err := userlib.HashKDF(file_uuid_bytes, []byte("mac counter val"))
			if err != nil {
				return err
			}
			uuid_mac_counter_val, err := uuid.FromBytes(uuid_mac_counter_val_bytes[:16])
			if err != nil {
				return err
			}
			userlib.DatastoreSet(uuid_mac_val, mac_val)
			userlib.DatastoreSet(uuid_mac_counter_val, mac_counter)

			marshal_info, err := json.Marshal(info)
			if err != nil {
				return err
			}
			PKEEncKey, ok := userlib.KeystoreGet(userdata.Username + "pke")
			if !ok {
				return errors.New("x")
			}
			enc_marshal_info, err := userlib.PKEEnc(PKEEncKey, marshal_info)
			if err != nil {
				return err
			}
			userlib.DatastoreSet(uuid_stuff, enc_marshal_info) // placed the mapping to info for the owner

			return nil
		}

		// this is a shared user, not the owner
		/* 
			*
			*
			*
			--- If user is a shared user, not the owner, and file exists ---
			*
			*
			*
		*/
		invPtr, err := uuid.FromBytes(invPtr_bytes)
		if err != nil {
			return err
		}
		enc_marshal_info, ok := userlib.DatastoreGet(invPtr)
		if !ok {
			return errors.New("revoked access")
		}

		info, err = userlib.PKEDec(userdata.PKEDecKey, enc_marshal_info)
		if err != nil {
			return err
		}
		var info_Obj Info
		err = json.Unmarshal(info, &info_Obj) // info_Obj is the actual decrypted unmarshalled info object
		if err != nil {
			return err
		}
		uuid_file_bytes := info_Obj.Uuid_file // this uuid_file is in byte form
		uuid_file, err := uuid.FromBytes(uuid_file_bytes) // uuid_file in of type uuid.UUID
		if err != nil {
			return err
		}
		uuid_counter_bytes, err := userlib.HashKDF(uuid_file_bytes, []byte("counter"))
		if err != nil {
			return err
		}
		uuid_counter, err := uuid.FromBytes(uuid_counter_bytes)
		if err != nil {
			return err
		}

		root_key := info_Obj.RootKey
		sym_key, MAC_key, err := EncMacKeysFromRoot(root_key, "enc", "mac")
		if err != nil {
			return err
		}
		uuid_mac_val_bytes, err := userlib.HashKDF(uuid_file_bytes, []byte("mac val"))
		if err != nil {
			return err
		}
		uuid_mac_val, err := uuid.FromBytes(uuid_mac_val_bytes[:16])
		if err != nil {
			return err
		}
		MAC_val, ok := userlib.DatastoreGet(uuid_mac_val)
		if !ok {
			return errors.New("x")
		}

		uuid_mac_counter_val_bytes, err := userlib.HashKDF(uuid_file_bytes, []byte("mac counter val"))
		if err != nil {
			return err
		}
		uuid_mac_counter_val, err := uuid.FromBytes(uuid_mac_counter_val_bytes[:16])
		if err != nil {
			return err
		}
		MAC_counter, ok := userlib.DatastoreGet(uuid_mac_counter_val)
		if !ok {
			return errors.New("x")
		}


		enc_file, ok := userlib.DatastoreGet(uuid_file)
		if !ok {
			return errors.New("error")
		}
		MAC_check, err := userlib.HMACEval(MAC_key, enc_file)
		if err != nil {
			return err
		}
		if !userlib.HMACEqual(MAC_val, MAC_check) {
			return errors.New("malicious tampering detected")
		}
		enc_counter, ok := userlib.DatastoreGet(uuid_counter)
		if !ok {
			return errors.New("error")
		}
		MAC_check, err = userlib.HMACEval(MAC_key, enc_counter)
		if err != nil {
			return err
		}
		if !userlib.HMACEqual(MAC_counter, MAC_check) {
			return errors.New("malicious tampering detected")
		}

		// for file
		marshal_file := userlib.SymDec(sym_key, enc_file)
		var file File
		err = json.Unmarshal(marshal_file, &file)
		if err != nil {
			return err
		}


		CTFI_uuid_bytes, err := userlib.HashKDF(uuid_file_bytes, []byte("children map"))
		if err != nil {
			return err
		}
		CTFI_MAC_uuid_bytes, err := userlib.HashKDF(CTFI_uuid_bytes[:16], []byte("mac"))
		if err != nil {
			return err
		}
		CTFI_uuid, err := uuid.FromBytes(CTFI_uuid_bytes[:16])
		if err != nil {
			return err
		}
		CTFI_MAC_uuid, err := uuid.FromBytes(CTFI_MAC_uuid_bytes[:16])
		if err != nil {
			return err
		}
		CTFI_MAC_val, ok := userlib.DatastoreGet(CTFI_MAC_uuid)
		if !ok {
			return errors.New("error")
		}

		enc_marshal_CTFI, ok := userlib.DatastoreGet(CTFI_uuid)
		if !ok {
			return errors.New("error")
		}
		MAC_check, err = userlib.HMACEval(MAC_key, enc_marshal_CTFI)
		if err != nil {
			return err
		}
		if !userlib.HMACEqual(CTFI_MAC_val, MAC_check) {
			return errors.New("malicious tampering")
		}
		marshal_CTFI := userlib.SymDec(sym_key, enc_marshal_CTFI)
		var CTFI map[string][2]string
		err = json.Unmarshal(marshal_CTFI, &CTFI)
		if err != nil {
			return err
		}

		pair, ok := CTFI[userdata.Username]
		if !ok {
			return errors.New("not shared user")
		}
		if pair[0] != filename {
			return errors.New("malicious activity")
		}
		if string(invPtr_bytes) != pair[1] {
			return errors.New("malicious activity")
		}

		file.Content = content
		marshal_file, err = json.Marshal(file)
		if err != nil {
			return err
		}

		enc_marshal_file, MAC_val, err := EncThenMac(MAC_key, sym_key, marshal_file)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(uuid_file, enc_marshal_file) // update the encrypted file mapping to the new encrypted file

		marshal_zero, err := json.Marshal(0)
		if err != nil {
			return err
		}
		enc_counter, MAC_counter, err = EncThenMac(MAC_key, sym_key, marshal_zero)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(uuid_counter, enc_counter) // update the counter value for the file back to 0

		userlib.DatastoreSet(uuid_mac_val, MAC_val)
		userlib.DatastoreSet(uuid_mac_counter_val, MAC_counter)

		return nil
	}
	/* 
		*
		*
		*
		--- If owner has the file ---
		*
		*
		*
	*/
	var info_Obj Info
	marshal_info, err := userlib.PKEDec(userdata.PKEDecKey, info)
	if err != nil {
		return err
	}
	err = json.Unmarshal(marshal_info, &info_Obj) // info_Obj is the actual decrypted unmarshalled info object
	if err != nil {
		return err
	}
	uuid_file_bytes := info_Obj.Uuid_file // this uuid_file is in byte form
	uuid_file, err := uuid.FromBytes(uuid_file_bytes) // uuid_file in of type uuid.UUID
	if err != nil {
		return err
	}
	uuid_counter_bytes, err := userlib.HashKDF(uuid_file_bytes, []byte("counter"))
	if err != nil {
		return err
	}
	uuid_counter, err := uuid.FromBytes(uuid_counter_bytes[:16])
	if err != nil {
		return err
	}

	root_key := info_Obj.RootKey
	sym_key, MAC_key, err := EncMacKeysFromRoot(root_key, "enc", "mac")
	if err != nil {
		return err
	}
	uuid_mac_val_bytes, err := userlib.HashKDF(uuid_file_bytes, []byte("mac val"))
	if err != nil {
		return err
	}
	uuid_mac_val, err := uuid.FromBytes(uuid_mac_val_bytes[:16])
	if err != nil {
		return err
	}
	MAC_val, ok := userlib.DatastoreGet(uuid_mac_val)
	if !ok {
		return errors.New("error")
	}

	uuid_mac_counter_val_bytes, err := userlib.HashKDF(uuid_file_bytes, []byte("mac counter val"))
	if err != nil {
		return err
	}
	uuid_mac_counter_val, err := uuid.FromBytes(uuid_mac_counter_val_bytes[:16])
	if err != nil {
		return err
	}
	MAC_counter, ok := userlib.DatastoreGet(uuid_mac_counter_val)
	if !ok {
		return errors.New("error")
	}

	enc_file, ok := userlib.DatastoreGet(uuid_file)
	if !ok {
		return errors.New("error")
	}
	MAC_check, err := userlib.HMACEval(MAC_key, enc_file)
	if err != nil {
		return err
	}
	equal := userlib.HMACEqual(MAC_val, MAC_check)
	if !equal {
		return errors.New("malicious tampering detected")
	}
	enc_counter, ok := userlib.DatastoreGet(uuid_counter)
	if !ok {
		return errors.New("error")
	}
	MAC_check, err = userlib.HMACEval(MAC_key, enc_counter)
	if err != nil {
		return err
	}
	equal = userlib.HMACEqual(MAC_counter, MAC_check)
	if !equal {
		return errors.New("malicious tampering detected")
	}

	// for counter
	marshal_zero, err := json.Marshal(0)
	if err != nil {
		return err
	}
	enc_counter, MAC_counter, err = EncThenMac(MAC_key, sym_key, marshal_zero)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(uuid_counter, enc_counter) // update the counter value for the file back to 0

	// for file
	marshal_file := userlib.SymDec(sym_key, enc_file)
	var file File
	err = json.Unmarshal(marshal_file, &file)
	if err != nil {
		return err
	}

	if file.OwnerName != userdata.Username {
		return errors.New("malicious activity")
	}
	if file.FileName != filename {
		return errors.New("malicious activity")
	}

	file.Content = content
	marshal_file, err = json.Marshal(file)
	if err != nil {
		return err
	}

	enc_marshal_file, MAC_val, err := EncThenMac(MAC_key, sym_key, marshal_file)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(uuid_file, enc_marshal_file) // update the encrypted file mapping to the new encrypted file

	userlib.DatastoreSet(uuid_mac_val, MAC_val)
	userlib.DatastoreSet(uuid_mac_counter_val, MAC_counter)

	CTFI_uuid_bytes, err := userlib.HashKDF(uuid_file_bytes, []byte("children map"))
	if err != nil {
		return err
	}
	CTFI_MAC_uuid_bytes, err := userlib.HashKDF(CTFI_uuid_bytes[:16], []byte("mac"))
	if err != nil {
		return err
	}
	CTFI_uuid, err := uuid.FromBytes(CTFI_uuid_bytes[:16])
	if err != nil {
		return err
	}
	CTFI_MAC_uuid, err := uuid.FromBytes(CTFI_MAC_uuid_bytes[:16])
	if err != nil {
		return err
	}
	CTFI_MAC_val, ok := userlib.DatastoreGet(CTFI_MAC_uuid)
	if !ok {
		return errors.New("error")
	}
	

	enc_marshal_CTFI, ok := userlib.DatastoreGet(CTFI_uuid)
	if !ok {
		return errors.New("error")
	}
	MAC_check, err = userlib.HMACEval(MAC_key, enc_marshal_CTFI)
	if err != nil {
		return err
	}
	if !userlib.HMACEqual(CTFI_MAC_val, MAC_check) {
		return errors.New("malicious tampering")
	}
	marshal_CTFI := userlib.SymDec(sym_key, enc_marshal_CTFI)
	var CTFI map[string][2]string
	err = json.Unmarshal(marshal_CTFI, &CTFI)
	if err != nil {
		return err
	}

	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	uuid_stuff, err := uuid.FromBytes(userlib.Hash(append(userlib.Hash([]byte(userdata.Username)), userlib.Hash([]byte(filename))...))[:16]) // owner check
	if err != nil {
		return err
	}
	enc_marshal_info, ok := userlib.DatastoreGet(uuid_stuff)
	if !ok { // if not owner or does not exist
		uuid_stuff_2, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "0" + filename))[:16]) // shared user check
		if err != nil {
			return err
		}
		invPtr_bytes, ok := userlib.DatastoreGet(uuid_stuff_2)
		if !ok { // if file does not exist (first shared user mapping does not exist)
			return errors.New("don't have this file")
		}
		invPtr, err := uuid.FromBytes(invPtr_bytes)
		if err != nil {
			return err
		}
		enc_marshal_info, ok = userlib.DatastoreGet(invPtr)
		if !ok { // (second shared user mapping does not exist)
			return errors.New("don't have this file")
		}
	}

	// pull info and check MAC of counter
	var info_Obj Info	
	marshal_info, err := userlib.PKEDec(userdata.PKEDecKey, enc_marshal_info)
	if err != nil {
		return err
	}
	err = json.Unmarshal(marshal_info, &info_Obj) // info_Obj is the actual decrypted unmarshalled info object
	if err != nil {
		return err
	}
	uuid_file_bytes := info_Obj.Uuid_file // this uuid_file is in byte form
	uuid_counter_bytes, err := userlib.HashKDF(uuid_file_bytes, []byte("counter"))
	if err != nil {
		return err
	}
	uuid_counter, err := uuid.FromBytes(uuid_counter_bytes[:16])
	if err != nil {
		return err
	}

	root_key := info_Obj.RootKey
	sym_key, MAC_key, err := EncMacKeysFromRoot(root_key, "enc", "mac")
	if err != nil {
		return err
	}
	// uuid_mac_val_bytes, err := userlib.HashKDF(uuid_file_bytes, []byte("mac val"))
	// uuid_mac_val, err := uuid.FromBytes(uuid_mac_val_bytes[:16])
	// MAC_val, ok := userlib.DatastoreGet(uuid_mac_val)

	uuid_mac_counter_val_bytes, err := userlib.HashKDF(uuid_file_bytes, []byte("mac counter val"))
	if err != nil {
		return err
	}
	uuid_mac_counter_val, err := uuid.FromBytes(uuid_mac_counter_val_bytes[:16])
	if err != nil {
		return err
	}
	MAC_counter, ok := userlib.DatastoreGet(uuid_mac_counter_val)
	if !ok {
		return err
	}


	enc_marshal_counter, ok := userlib.DatastoreGet(uuid_counter)
	if !ok {
		return err
	}
	MAC_check, err := userlib.HMACEval(MAC_key, enc_marshal_counter)
	if err != nil {
		return err
	}
	if !userlib.HMACEqual(MAC_counter, MAC_check) {
		return errors.New("tampering")
	}

	marshal_counter := userlib.SymDec(sym_key, enc_marshal_counter)
	var counter int64
	err = json.Unmarshal(marshal_counter, &counter)
	if err != nil {
		return err
	}
	counter = counter + 1
	marshal_counter, err = json.Marshal(counter)
	if err != nil {
		return err
	}
	enc_marshal_counter, MAC_counter_val, err := EncThenMac(MAC_key, sym_key, marshal_counter)
	if err != nil {
		return err
	}

	userlib.DatastoreSet(uuid_mac_counter_val, MAC_counter_val)
	userlib.DatastoreSet(uuid_counter, enc_marshal_counter)


	CTFI_uuid_bytes, err := userlib.HashKDF(uuid_file_bytes, []byte("children map"))
	if err != nil {
		return err
	}
	CTFI_MAC_uuid_bytes, err := userlib.HashKDF(CTFI_uuid_bytes[:16], []byte("mac"))
	if err != nil {
		return err
	}
	CTFI_uuid, err := uuid.FromBytes(CTFI_uuid_bytes[:16])
	if err != nil {
		return err
	}
	CTFI_MAC_uuid, err := uuid.FromBytes(CTFI_MAC_uuid_bytes[:16])
	if err != nil {
		return err
	}
	CTFI_MAC_val, ok := userlib.DatastoreGet(CTFI_MAC_uuid)
	if !ok {
		return err
	}

	enc_marshal_CTFI, ok := userlib.DatastoreGet(CTFI_uuid)
	if !ok {
		return err
	}
	MAC_check, err = userlib.HMACEval(MAC_key, enc_marshal_CTFI)
	if err != nil {
		return err
	}
	if !userlib.HMACEqual(CTFI_MAC_val, MAC_check) {
		return errors.New("malicious tampering")
	}
	marshal_CTFI := userlib.SymDec(sym_key, enc_marshal_CTFI)
	var CTFI map[string][2]string
	err = json.Unmarshal(marshal_CTFI, &CTFI)
	if err != nil {
		return err
	}

	// putting the content of the append
	uuid_next_append_bytes, err := userlib.HashKDF(uuid_file_bytes, marshal_counter)
	if err != nil {
		return err
	}
	uuid_next_append, err := uuid.FromBytes(uuid_next_append_bytes[:16])
	if err != nil {
		return err
	}
	enc_content, MAC_content, err := EncThenMac(MAC_key, sym_key, content)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(uuid_next_append, enc_content)

	uuid_MAC_content_bytes, err := userlib.HashKDF(uuid_next_append_bytes[:16], []byte("mac"))
	if err != nil {
		return err
	}
	uuid_MAC_content, err := uuid.FromBytes(uuid_MAC_content_bytes[:16])
	if err != nil {
		return err
	}
	userlib.DatastoreSet(uuid_MAC_content, MAC_content)

	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	uuid_stuff, err := uuid.FromBytes(userlib.Hash(append(userlib.Hash([]byte(userdata.Username)), userlib.Hash([]byte(filename))...))[:16]) // owner check
	if err != nil {
		return nil, err
	}
	enc_marshal_info, ok := userlib.DatastoreGet(uuid_stuff)
	if !ok { // if not owner or does not exist
		uuid_stuff_2, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "0" + filename))[:16]) // shared user check
		if err != nil {
			return nil, err
		}
		invPtr_bytes, ok := userlib.DatastoreGet(uuid_stuff_2)
		if !ok { // if file does not exist (first shared user mapping does not exist)
			return nil, errors.New("don't have this file")
		}
		invPtr, err := uuid.FromBytes(invPtr_bytes)


		if err != nil {
			return nil, err
		}
		enc_marshal_info, ok = userlib.DatastoreGet(invPtr)
		if !ok { // (second shared user mapping does not exist)
			return nil, errors.New("don't have this file")
		}
	}


	var info_Obj Info
	marshal_info, err := userlib.PKEDec(userdata.PKEDecKey, enc_marshal_info)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(marshal_info, &info_Obj) // info_Obj is the actual decrypted unmarshalled info object
	if err != nil {
		return nil, err
	}
	uuid_file_bytes := info_Obj.Uuid_file // this uuid_file is in byte form
	uuid_file, err := uuid.FromBytes(uuid_file_bytes)
	if err != nil {
		return nil, err
	}

	uuid_counter_bytes, err := userlib.HashKDF(uuid_file_bytes, []byte("counter"))
	if err != nil {
		return nil, err
	}
	uuid_counter, err := uuid.FromBytes(uuid_counter_bytes[:16])
	if err != nil {
		return nil, err
	}


	root_key := info_Obj.RootKey
	sym_key, MAC_key, err := EncMacKeysFromRoot(root_key, "enc", "mac")
	if err != nil {
		return nil, err
	}
	uuid_mac_val_bytes, err := userlib.HashKDF(uuid_file_bytes, []byte("mac val"))
	if err != nil {
		return nil, err
	}
	uuid_mac_val, err := uuid.FromBytes(uuid_mac_val_bytes[:16])
	if err != nil {
		return nil, err
	}
	MAC_val, ok := userlib.DatastoreGet(uuid_mac_val)
	if !ok {
		return nil, errors.New("error")
	}
	
	uuid_mac_counter_val_bytes, err := userlib.HashKDF(uuid_file_bytes, []byte("mac counter val"))
	if err != nil {
		return nil, err
	}
	uuid_mac_counter_val, err := uuid.FromBytes(uuid_mac_counter_val_bytes[:16])
	if err != nil {
		return nil, err
	}

	MAC_counter, ok := userlib.DatastoreGet(uuid_mac_counter_val)
	if !ok {
		return nil, errors.New("error")
	}




	enc_marshal_counter, ok := userlib.DatastoreGet(uuid_counter)
	if !ok {
		return nil, errors.New("error")
	}
	MAC_check, err := userlib.HMACEval(MAC_key, enc_marshal_counter)
	if err != nil {
		return nil, err
	}
	if !userlib.HMACEqual(MAC_counter, MAC_check) {
		return nil, errors.New("malicious tampering")
	}

	marshal_counter := userlib.SymDec(sym_key, enc_marshal_counter)
	var counter int64
	err = json.Unmarshal(marshal_counter, &counter)
	if err != nil {
		return nil, err
	}

	enc_marshal_file, ok := userlib.DatastoreGet(uuid_file)
	if !ok { // if file does not exist (first shared user mapping does not exist)
		return nil, errors.New("error")
	}

	MAC_check, err = userlib.HMACEval(MAC_key, enc_marshal_file)
	if err != nil {
		return nil, err
	}
	if !userlib.HMACEqual(MAC_val, MAC_check) {
		return nil, errors.New("malicious tampering")
	}
	marshal_file := userlib.SymDec(sym_key, enc_marshal_file)
	var file File
	err = json.Unmarshal(marshal_file, &file)
	var ret []byte
	ret = file.Content
	
	var i int64
	for i = 1; i <= counter; i++ {
		// fmt.Println("append index: " + fmt.Sprint(i)) // XDXD
		marshal_i, err := json.Marshal(i)
		if err != nil {
			return nil, err
		}
		uuid_next_append_bytes, err := userlib.HashKDF(uuid_file_bytes, marshal_i)
		if err != nil {
			return nil, err
		}
		uuid_next_append, err := uuid.FromBytes(uuid_next_append_bytes[:16])
		if err != nil {
			return nil, err
		}
		enc_append_i, ok := userlib.DatastoreGet(uuid_next_append)
		if !ok {
			return nil, errors.New("x")
		}

		// check MAC for each append
		uuid_MAC_content_bytes, err := userlib.HashKDF(uuid_next_append_bytes[:16], []byte("mac"))
		if err != nil {
			return nil, err
		}
		uuid_MAC_content, err := uuid.FromBytes(uuid_MAC_content_bytes[:16])
		if err != nil {
			return nil, err
		}
		MAC_val, ok := userlib.DatastoreGet(uuid_MAC_content) // continue from here, need to check MAC_check and MAC_check2
		if !ok { // if file does not exist (first shared user mapping does not exist)
			return nil, errors.New("error")
		}

		MAC_check, err := userlib.HMACEval(MAC_key, enc_append_i)

		if err != nil {
			return nil, err
		}
		if !userlib.HMACEqual(MAC_check, MAC_val) {
			return nil, errors.New("error")
		}

		// MAC_check passed, decrypt enc_append_i
		append_i := userlib.SymDec(sym_key, enc_append_i)
		ret = append(ret, append_i...)
	}
	return ret, err	
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (invitationPtr uuid.UUID, err error) {
	uuid_stuff, err := uuid.FromBytes(userlib.Hash(append(userlib.Hash([]byte(userdata.Username)), userlib.Hash([]byte(filename))...))[:16]) // owner check
	if err != nil {
		return uuid.Nil, err
	}
	enc_marshal_info, ok := userlib.DatastoreGet(uuid_stuff)
	if !ok { // if not owner or does not exist
		uuid_stuff_2, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "0" + filename))[:16]) // shared user check
		if err != nil {
			return uuid.Nil, err
		}
		invPtr_bytes, ok := userlib.DatastoreGet(uuid_stuff_2)
		if !ok { // if file does not exist (first shared user mapping does not exist)
			return uuid.Nil, errors.New("don't have this file")
		}
		invPtr, err := uuid.FromBytes(invPtr_bytes)
		if err != nil {
			return uuid.Nil, err
		}

		enc_marshal_info, ok = userlib.DatastoreGet(invPtr)
		if !ok { // (second shared user mapping does not exist)
			return uuid.Nil, errors.New("don't have this file")
		}
	}
	// user has access (owner or shared user)
	var info_Obj Info
	marshal_info, err := userlib.PKEDec(userdata.PKEDecKey, enc_marshal_info)
	if err != nil {
		return uuid.Nil, err
	}

	err = json.Unmarshal(marshal_info, &info_Obj) // info_Obj is the actual decrypted unmarshalled info object
	if err != nil {
		return uuid.Nil, err
	}
	uuid_file_bytes := info_Obj.Uuid_file // this uuid_file is in byte form
	// uuid_file, err := uuid.FromBytes(uuid_file_bytes)
	// uuid_counter_bytes, err := userlib.HashKDF(uuid_file_bytes, []byte("counter"))
	// uuid_counter, err := uuid.FromBytes(uuid_counter_bytes)

	// sym_key := info_Obj.SymKey
	rootKey := info_Obj.RootKey
	sym_key, MAC_key, err := EncMacKeysFromRoot(rootKey, "enc", "mac") // xdxd
	if err != nil {
		return uuid.Nil, err
	}
	// MAC_val := info_Obj.MacVal
	// MAC_counter := info_Obj.MacCounterVal

	uuid_user, err := uuid.FromBytes(userlib.Hash([]byte(recipientUsername))[:16])
	if err != nil {
		return uuid.Nil, err
	}
	_, ok = userlib.DatastoreGet(uuid_user)
	if !ok {
		return uuid.Nil, errors.New("recipient user does not exist")
	}

	encKey, ok := userlib.KeystoreGet(recipientUsername + "pke")
	if !ok {
		return uuid.Nil, errors.New("recipient user does not exist")
	}

	CTFI_uuid_bytes, err := userlib.HashKDF(uuid_file_bytes, []byte("children map"))
	if err != nil {
		return uuid.Nil, err
	}
	CTFI_MAC_uuid_bytes, err := userlib.HashKDF(CTFI_uuid_bytes[:16], []byte("mac"))
	if err != nil {
		return uuid.Nil, err
	}
	CTFI_uuid, err := uuid.FromBytes(CTFI_uuid_bytes[:16])
	if err != nil {
		return uuid.Nil, err
	}
	CTFI_MAC_uuid, err := uuid.FromBytes(CTFI_MAC_uuid_bytes[:16])
	if err != nil {
		return uuid.Nil, err
	}
	CTFI_MAC_val, ok := userlib.DatastoreGet(CTFI_MAC_uuid)
	if !ok {
		return uuid.Nil, errors.New("x")
	}

	enc_marshal_CTFI, ok := userlib.DatastoreGet(CTFI_uuid)
	if !ok {
		return uuid.Nil, errors.New("x")
	}
	MAC_check, err := userlib.HMACEval(MAC_key, enc_marshal_CTFI)
	if err != nil {
		return uuid.Nil, err
	}
	if !userlib.HMACEqual(CTFI_MAC_val, MAC_check) {
		return uuid.Nil, errors.New("malicious tampering")
	}
	marshal_CTFI := userlib.SymDec(sym_key, enc_marshal_CTFI)
	var CTFI map[string][2]string
	err = json.Unmarshal(marshal_CTFI, &CTFI)
	if err != nil {
		return uuid.Nil, err
	}
	
	// enc_marshal_info, err = userlib.PKEEnc(encKey, marshal_info)
	// if err != nil {
	// 	return err
	// }
	// userlib.DatastoreSet(invPtr, enc_marshal_info)


	// enc_marshall_info, err := userlib.PKEEnc(PKEEncKey, marshal_info)
	invPtr_bytes := userlib.RandomBytes(16)
	invPtr, err := uuid.FromBytes(invPtr_bytes)
	if err != nil {
		return uuid.Nil, err
	}
	invPtr_str := invPtr.String()

	CTFI[recipientUsername] = [2]string{"", invPtr_str} // maybe issue XDXD
	marshal_CTFI, err = json.Marshal(CTFI)
	if err != nil {
		return uuid.Nil, err
	}
	enc_marshal_CTFI, MAC_CTFI, err := EncThenMac(MAC_key, sym_key, marshal_CTFI)
	if err != nil {
		return uuid.Nil, err
	}
	userlib.DatastoreSet(CTFI_MAC_uuid, MAC_CTFI)
	userlib.DatastoreSet(CTFI_uuid, enc_marshal_CTFI)

	enc_marshal_info, err = userlib.PKEEnc(encKey, marshal_info)
	if err != nil {
		return uuid.Nil, err
	}
	userlib.DatastoreSet(invPtr, enc_marshal_info)
	

	enc_invPtr_bytes, err := userlib.PKEEnc(encKey, invPtr_bytes)
	if err != nil {
		return uuid.Nil, err
	}

	sig, err := userlib.DSSign(userdata.DSSignKey, enc_invPtr_bytes)
	if err != nil {
		return uuid.Nil, err
	}

	fake_invPtr_bytes := userlib.RandomBytes(16)
	fake_invPtr, err := uuid.FromBytes(fake_invPtr_bytes)
	if err != nil {
		return uuid.Nil, err
	}

	uuid_DS_bytes, err := userlib.HashKDF(fake_invPtr_bytes, []byte("ds"))
	if err != nil {
		return uuid.Nil, err
	}
	uuid_DS, err := uuid.FromBytes(uuid_DS_bytes[:16])
	if err != nil {
		return uuid.Nil, err
	}

	userlib.DatastoreSet(uuid_DS, sig)
	userlib.DatastoreSet(fake_invPtr, enc_invPtr_bytes)

	return fake_invPtr, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	uuid_stuff, err := uuid.FromBytes(userlib.Hash(append(userlib.Hash([]byte(userdata.Username)), userlib.Hash([]byte(filename))...))[:16]) // owner check
	if err != nil {
		return err
	}
	_, ok := userlib.DatastoreGet(uuid_stuff)
	if ok { // if owner
		return errors.New("has this filename in directory")
	} else { // not owner
		uuid_stuff_2, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "0" + filename))[:16]) // shared user check
		if err != nil {
			return err
		}
		_, ok := userlib.DatastoreGet(uuid_stuff_2)
		if ok { // is shared user who has the filename
			return errors.New("has this filename in directory")
		}
	}
	fake_invPtr := invitationPtr
	fake_invPtr_bytes := fake_invPtr[:]
	
	uuid_DS_bytes, err := userlib.HashKDF(fake_invPtr_bytes, []byte("ds"))
	if err != nil {
		return err
	}

	uuid_DS, err := uuid.FromBytes(uuid_DS_bytes[:16])
	if err != nil {
		return err
	}

	sig, ok := userlib.DatastoreGet(uuid_DS)
	if !ok {
		return errors.New("accepted before")
	}

	verify_key, ok := userlib.KeystoreGet(senderUsername + "ds")
	if !ok {
		return errors.New("x")
	}

	enc_invPtr_bytes, ok := userlib.DatastoreGet(fake_invPtr)
	if !ok {
		return errors.New("x")
	}

	err = userlib.DSVerify(verify_key, enc_invPtr_bytes, sig)
	if err != nil {
		return errors.New("wrong sender")
	}

	userlib.DatastoreDelete(uuid_DS)
	userlib.DatastoreDelete(fake_invPtr)

	invPtr_bytes, err := userlib.PKEDec(userdata.PKEDecKey, enc_invPtr_bytes)
	if err != nil {
		return err
	}
	invPtr, err := uuid.FromBytes(invPtr_bytes)
	if err != nil {
		return err
	}

	enc_marshal_info, ok := userlib.DatastoreGet(invPtr)
	if !ok {
		return errors.New("invitation pointer has been revoked or invalid invitation pointer")
	}

	// update [children -> filename, invPtr] mapping the file object
	marshal_info, err := userlib.PKEDec(userdata.PKEDecKey, enc_marshal_info)
	if err != nil {
		return err
	}
	var info_Obj Info
	err = json.Unmarshal(marshal_info, &info_Obj)
	if err != nil {
		return err
	}
	uuid_file_bytes := info_Obj.Uuid_file // this uuid_file is in byte form
	uuid_file, err := uuid.FromBytes(uuid_file_bytes)
	if err != nil {
		return err
	}
	uuid_counter_bytes, err := userlib.HashKDF(uuid_file_bytes, []byte("counter"))
	if err != nil {
		return err
	}
	uuid_counter, err := uuid.FromBytes(uuid_counter_bytes[:16])
	if err != nil {
		return err
	}

	root_key := info_Obj.RootKey
	sym_key, MAC_key, err := EncMacKeysFromRoot(root_key, "enc", "mac")
	if err != nil {
		return err
	}
	uuid_mac_val_bytes, err := userlib.HashKDF(uuid_file_bytes, []byte("mac val"))
	if err != nil {
		return err
	}
	uuid_mac_val, err := uuid.FromBytes(uuid_mac_val_bytes[:16])
	if err != nil {
		return err
	}
	MAC_val, ok := userlib.DatastoreGet(uuid_mac_val)
	if !ok {
		return errors.New("x")
	}
	
	uuid_mac_counter_val_bytes, err := userlib.HashKDF(uuid_file_bytes, []byte("mac counter val"))
	if err != nil {
		return err
	}
	uuid_mac_counter_val, err := uuid.FromBytes(uuid_mac_counter_val_bytes[:16])
	if err != nil {
		return err
	}
	MAC_counter, ok := userlib.DatastoreGet(uuid_mac_counter_val)
	if !ok {
		return errors.New("x")
	}

	enc_marshal_file, ok := userlib.DatastoreGet(uuid_file)
	if !ok {
		return errors.New("x")
	}
	MAC_check, err := userlib.HMACEval(MAC_key, enc_marshal_file)
	if err != nil {
		return err
	}
	if !userlib.HMACEqual(MAC_check, MAC_val) {
		return errors.New("malicious tampering of file")
	}

	enc_marshal_counter, ok := userlib.DatastoreGet(uuid_counter)
	if !ok {
		return errors.New("x")
	}
	MAC_val, err = userlib.HMACEval(MAC_key, enc_marshal_counter)
	if err != nil {
		return err
	}
	if !userlib.HMACEqual(MAC_counter, MAC_val) {
		return errors.New("malicious tampering of counter")
	}

	marshal_file := userlib.SymDec(sym_key, enc_marshal_file)
	var file File
	err = json.Unmarshal(marshal_file, &file)
	if err != nil {
		return err
	}
	
	CTFI_uuid_bytes, err := userlib.HashKDF(uuid_file_bytes, []byte("children map"))
	if err != nil {
		return err
	}
	CTFI_MAC_uuid_bytes, err := userlib.HashKDF(CTFI_uuid_bytes[:16], []byte("mac"))
	if err != nil {
		return err
	}
	CTFI_uuid, err := uuid.FromBytes(CTFI_uuid_bytes[:16])
	if err != nil {
		return err
	}
	CTFI_MAC_uuid, err := uuid.FromBytes(CTFI_MAC_uuid_bytes[:16])
	if err != nil {
		return err
	}
	CTFI_MAC_val, ok := userlib.DatastoreGet(CTFI_MAC_uuid)
	if !ok {
		return errors.New("x")
	}

	enc_marshal_CTFI, ok := userlib.DatastoreGet(CTFI_uuid)
	if !ok {
		return errors.New("x")
	}
	MAC_check, err = userlib.HMACEval(MAC_key, enc_marshal_CTFI)
	if err != nil {
		return err
	}
	if !userlib.HMACEqual(CTFI_MAC_val, MAC_check) {
		return errors.New("malicious tampering")
	}
	marshal_CTFI := userlib.SymDec(sym_key, enc_marshal_CTFI)
	var CTFI map[string][2]string
	err = json.Unmarshal(marshal_CTFI, &CTFI)
	if err != nil {
		return err
	}

	_, ok = CTFI[userdata.Username]
	if !ok { // check if this user already exists in file's children mapping
		return errors.New("don't have mapping")
	}

	_, ok = file.SenderToRecipient[userdata.Username]
	if ok { // check if user being shared to is in SenderToRecipient mapping keyset
		return errors.New("accepted this invitation pointer before")
	}

	invPtr_str := invPtr.String()
	CTFI[userdata.Username] = [2]string{filename, invPtr_str}
	marshal_CTFI, err = json.Marshal(CTFI)
	if err != nil {
		return err
	}
	enc_marshal_CTFI, MAC_CTFI_val, err := EncThenMac(MAC_key, sym_key, marshal_CTFI)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(CTFI_MAC_uuid, MAC_CTFI_val)
	userlib.DatastoreSet(CTFI_uuid, enc_marshal_CTFI)

	file.SenderToRecipient[senderUsername] = append(file.SenderToRecipient[senderUsername], userdata.Username)
	file.SenderToRecipient[userdata.Username] = []string{}


	// remarshal and encrypt the file object for each shared user and the owner
	marshal_file, err = json.Marshal(file)
	if err != nil {
		return err
	}

	IV := userlib.RandomBytes(16)
	enc_marshall_file := userlib.SymEnc(sym_key, IV, marshal_file)

	mac_val, err := userlib.HMACEval(MAC_key, enc_marshall_file)
	userlib.DatastoreSet(uuid_mac_val, mac_val)

	if err != nil {
		return err
	}
	// update mapping from uuid_file -> file object
	userlib.DatastoreSet(uuid_file, enc_marshall_file)

	// update mapping for each mapping to info
	// update mapping for owner

	uuid_stuff_2, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "0" + filename))[:16])
	if err != nil {
		return err
	}
	userlib.DatastoreSet(uuid_stuff_2, invPtr_bytes)
	
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	// update mapping in file (child mapping)
	// update uuid_file -> file object mapping (after we update file object)
	// update info for everyone
	uuid_stuff, err := uuid.FromBytes(userlib.Hash(append(userlib.Hash([]byte(userdata.Username)), userlib.Hash([]byte(filename))...))[:16]) // owner check
	if err != nil {
		return err
	}
	enc_marshal_info, ok := userlib.DatastoreGet(uuid_stuff)
	if !ok { // if not owner
		return errors.New("not owner of file")
	}
	marshal_info, err := userlib.PKEDec(userdata.PKEDecKey, enc_marshal_info)
	if err != nil {
		return err
	}
	var info_Obj Info
	err = json.Unmarshal(marshal_info, &info_Obj)
	if err != nil {
		return err
	}
	file_uuid_bytes := info_Obj.Uuid_file // this uuid_file is in byte form
	file_uuid, err := uuid.FromBytes(file_uuid_bytes)
	if err != nil {
		return err
	}
	uuid_counter_bytes, err := userlib.HashKDF(file_uuid_bytes, []byte("counter"))
	if err != nil {
		return err
	}
	uuid_counter, err := uuid.FromBytes(uuid_counter_bytes[:16])
	if err != nil {
		return err
	}

	root_key := info_Obj.RootKey
	sym_key_old, MAC_key_old, err := EncMacKeysFromRoot(root_key, "enc", "mac")
	if err != nil {
		return err
	}
	uuid_mac_val_bytes, err := userlib.HashKDF(file_uuid_bytes, []byte("mac val"))
	if err != nil {
		return err
	}
	uuid_mac_val, err := uuid.FromBytes(uuid_mac_val_bytes[:16])
	if err != nil {
		return err
	}
	MAC_val, ok := userlib.DatastoreGet(uuid_mac_val)
	if !ok {
		return errors.New("x")
	}

	uuid_mac_counter_val_bytes, err := userlib.HashKDF(file_uuid_bytes, []byte("mac counter val"))
	if err != nil {
		return err
	}
	uuid_mac_counter_val, err := uuid.FromBytes(uuid_mac_counter_val_bytes[:16])
	if err != nil {
		return err
	}
	MAC_counter, ok := userlib.DatastoreGet(uuid_mac_counter_val)
	if !ok {
		return errors.New("x")
	}

	enc_marshal_file, ok := userlib.DatastoreGet(file_uuid)
	if !ok {
		return errors.New("x")
	}
	MAC_check, err := userlib.HMACEval(MAC_key_old, enc_marshal_file)
	if err != nil {
		return err
	}
	if !userlib.HMACEqual(MAC_check, MAC_val) {
		return errors.New("malicious tampering of file")
	}

	enc_marshal_counter, ok := userlib.DatastoreGet(uuid_counter)
	if !ok {
		return errors.New("x")
	}
	MAC_check, err = userlib.HMACEval(MAC_key_old, enc_marshal_counter)
	if err != nil {
		return err
	}
	if !userlib.HMACEqual(MAC_counter, MAC_check) {
		return errors.New("malicious tampering of counter")
	}

	marshal_counter := userlib.SymDec(sym_key_old, enc_marshal_counter)
	marshal_file := userlib.SymDec(sym_key_old, enc_marshal_file)
	var file File
	err = json.Unmarshal(marshal_file, &file)
	if err != nil {
		return err
	}

	if file.OwnerName != userdata.Username {
		return errors.New("not owner of file")
	}
	if file.FileName != filename {
		return errors.New("filename incorrect")
	}

	CTFI_uuid_bytes, err := userlib.HashKDF(file_uuid_bytes, []byte("children map"))
	if err != nil {
		return err
	}
	CTFI_MAC_uuid_bytes, err := userlib.HashKDF(CTFI_uuid_bytes[:16], []byte("mac"))
	if err != nil {
		return err
	}
	CTFI_uuid, err := uuid.FromBytes(CTFI_uuid_bytes[:16])
	if err != nil {
		return err
	}
	CTFI_MAC_uuid, err := uuid.FromBytes(CTFI_MAC_uuid_bytes[:16])
	if err != nil {
		return err
	}
	
	CTFI := make(map[string][2]string)

	enc_marshal_CTFI, ok := userlib.DatastoreGet(CTFI_uuid)
	if !ok {
		return errors.New("x")
	}
	CTFI_MAC_val, ok := userlib.DatastoreGet(CTFI_MAC_uuid)
	if !ok {
		return errors.New("x")
	}


	if err != nil {
		return err
	}
	mac_check, err := userlib.HMACEval(MAC_key_old, enc_marshal_CTFI)
	if err != nil {
		return err
	}
	if !userlib.HMACEqual(mac_check, CTFI_MAC_val) {
		return errors.New("malcious")
	}

	marshal_CTFI := userlib.SymDec(sym_key_old, enc_marshal_CTFI)
	err = json.Unmarshal(marshal_CTFI, &CTFI)
	if err != nil {
		return err
	}

	pair, ok := CTFI[recipientUsername]
	if !ok {
		return errors.New("revoke user does not have access")
	}

	if pair[0] != "" {
		val, ok := file.SenderToRecipient[userdata.Username]
		if !ok {
			return errors.New("you don't have access or malicous tampering")
		}
		i := indexOf(val, recipientUsername)
		if i == -1 {
			return errors.New("revoke user does not have access2")
		}
		file.SenderToRecipient[userdata.Username] = remove(val, i)
	}

	list := []string{recipientUsername}

	for len(list) > 0 {
		curr := list[0]
		list = list[1:] // curr is name of the current popped user from list
		list = append(list, file.SenderToRecipient[curr]...) // update list by popping first element and appending the children of the popped user

		delete(file.SenderToRecipient, curr)

		pair := CTFI[curr]
		curr_filename := pair[0]
		invPtr_str := pair[1]
		invPtr, err := uuid.Parse(invPtr_str)
		if err != nil {
			return err
		}
		invPtr_bytes := invPtr[:]
		if err != nil {
			return err
		}
		uuid_stuff_2, err := uuid.FromBytes(userlib.Hash([]byte(curr + "0" + curr_filename))[:16]) // shared user check
		if err != nil {
			return err
		}
		if pair[0] != "" { // calling revoke on user that hasn't accepted yet
			invPtr2_bytes, ok := userlib.DatastoreGet(uuid_stuff_2)
			if !ok {
				return errors.New("x")
			}
			if !compare(invPtr_bytes, invPtr2_bytes) {
				return errors.New("tampering")
			}
	
			userlib.DatastoreDelete(uuid_stuff_2)
		}
		userlib.DatastoreDelete(invPtr)
		delete(CTFI, curr)
	}
	marshal_file, err = json.Marshal(file)
	if err != nil {
		return err
	}
	marshal_CTFI, err = json.Marshal(CTFI)
	if err != nil {
		return err
	}
	root_key = userlib.RandomBytes(16) // new key
	sym_key_new, mac_key_new, err := EncMacKeysFromRoot(root_key, "enc", "mac") // new key
	if err != nil {
		return err
	}

	info_Obj.RootKey = root_key

	enc_marshal_file, macVal, err := EncThenMac(mac_key_new, sym_key_new, marshal_file)
	if err != nil {
		return err
	}
	enc_marshal_CTFI, mac_CTFI_Val, err := EncThenMac(mac_key_new, sym_key_new, marshal_CTFI)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(file_uuid, enc_marshal_file)
	userlib.DatastoreSet(CTFI_uuid, enc_marshal_CTFI)
	userlib.DatastoreSet(CTFI_MAC_uuid, mac_CTFI_Val)
	
	userlib.DatastoreSet(uuid_mac_val, macVal)

	enc_marshal_counter, macCounter, err := EncThenMac(mac_key_new, sym_key_new, marshal_counter)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(uuid_counter, enc_marshal_counter)
	userlib.DatastoreSet(uuid_mac_counter_val, macCounter)

	// update info for everyone (info_Obj has been updates, just need to re-encrypt for everyone (owner + shared users) and update mappings in datastore)
	// update mapping to info for owner
	marshal_info, err = json.Marshal(info_Obj)
	if err != nil {
		return err
	}
	PKEKey, ok := userlib.KeystoreGet(userdata.Username + "pke")
	if !ok {
		return errors.New("x")
	}
	enc_marshal_info, err = userlib.PKEEnc(PKEKey, marshal_info)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(uuid_stuff, enc_marshal_info)

	// update mapping invPtr -> info for all shared users
	for child, pair := range CTFI { // placing the updated mapping to info for each of the children
		// filename := pair[0]
		invPtr_Str := pair[1]
		enc_Key, ok := userlib.KeystoreGet(child + "pke")
		if !ok {
			return errors.New("dne")
		}
		enc_marshal_info, err = userlib.PKEEnc(enc_Key, marshal_info)
		if err != nil {
			return err
		}
		invPtr, err := uuid.Parse(invPtr_Str)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(invPtr, enc_marshal_info)
	}

	var counter int64
	err = json.Unmarshal(marshal_counter, &counter)
	if err != nil {
		return err
	}
	var i int64

	for i = 1; i <= counter; i++ {
		// fmt.Println("append index: " + fmt.Sprint(i)) // XDXD
		marshal_i, err := json.Marshal(i)
		if err != nil {
			return err
		}
		uuid_next_append_bytes, err := userlib.HashKDF(file_uuid_bytes, marshal_i)
		if err != nil {
			return err
		}
		uuid_next_append, err := uuid.FromBytes(uuid_next_append_bytes[:16])
		if err != nil {
			return err
		}
		enc_append_i_content, ok := userlib.DatastoreGet(uuid_next_append)
		if !ok {
			return errors.New("x")
		}

		uuid_MAC_content_bytes, err := userlib.HashKDF(uuid_next_append_bytes[:16], []byte("mac"))
		if err != nil {
			return err
		}
		uuid_MAC_content, err := uuid.FromBytes(uuid_MAC_content_bytes[:16])
		if err != nil {
			return err
		}
		MAC_val, ok := userlib.DatastoreGet(uuid_MAC_content) // continue from here, need to check MAC_check and MAC_check2
		if !ok { // if file does not exist (first shared user mapping does not exist)
			return errors.New("error")
		}

		MAC_check, err := userlib.HMACEval(MAC_key_old, enc_append_i_content)
		if err != nil {
			return err
		}
		if !userlib.HMACEqual(MAC_check, MAC_val) {
			return errors.New("error")
		}

		append_i_content := userlib.SymDec(sym_key_old, enc_append_i_content)
		enc_append_i_content, MAC_append_i_content, err := EncThenMac(mac_key_new, sym_key_new, append_i_content)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(uuid_next_append, enc_append_i_content)
		userlib.DatastoreSet(uuid_MAC_content, MAC_append_i_content)
	}

	return nil
}
