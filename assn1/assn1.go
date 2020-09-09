package assn1

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (

	// You neet to add with
	// go get github.com/fenilfadadu/CS628-assn1/userlib
	"github.com/fenilfadadu/CS628-assn1/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...
	"encoding/json"

	// Likewise useful for debugging etc
	"encoding/hex"

	// UUIDs are generated right based on the crypto RNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys
	"strings"

	// Want to import errors
	"errors"
)

const Encryption_Key_Size = 32
const Password_key_length = Encryption_Key_Size
const FileUUIDLength = 16

// This serves two purposes: It shows you some useful primitives and
// it suppresses warnings for items not being imported
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var key *userlib.PrivateKey
	key, _ = userlib.GenerateRSAKey()
	userlib.DebugMsg("Key is %v", key)
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

// The structure definition for a user record
type User struct {
	Username               string
	Password_hash          []byte
	PrivateKey             *userlib.PrivateKey
	Key                    string                            //The K in <K,V> pair in the data store used to identify the user data structure
	File_meta_data_locator map[string]File_Meta_Data_Locator // To locate the meta data of the file

	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

// For converting to JSON
type User_Data_Store struct {
	User_Data    []byte
	Content_hash []byte
}

type File_Meta_Data_Locator struct {
	File_UUID   uuid.UUID
	Encrypt_Key []byte
}

type UUID_Hash_Pair struct {
	File_Part_UUID   uuid.UUID
	File_Part_Hash   []byte
	File_Encrypt_Key []byte
}

type File_Meta_Data struct {
	FileParts_Map       []UUID_Hash_Pair
	File_Meta_Data_UUID uuid.UUID
}

// Converting to JSON
type File_Meta_Data_Store struct {
	File_Meta_Data_JSON []byte
	Content_Hash        []byte
}

type File_Part struct {
	Content      []byte
	Content_Hash []byte
}

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored
// User data: the name used in the datastore should not be guessable
// without also knowing the password and username.

// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the user has a STRONG password
func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	// Searching if user name is occupied in Key Store
	_, already_user := userlib.KeystoreGet(username)
	if already_user {
		err = errors.New("Username already taken.")
		return
	}

	// Generating key to store user DS in Data Store
	UserMetaData := username + password
	UserDataStoreKeyBytes := []byte(UserMetaData)
	password_bytes := []byte(password)
	mac := userlib.NewHMAC(password_bytes)
	mac.Write(UserDataStoreKeyBytes)
	UserDataStoreKeyBytes = mac.Sum(nil)
	UserDataStoreKey := hex.EncodeToString(UserDataStoreKeyBytes[:])

	// Searching if the map key is already occupied in Data Store map
	_, already_user = userlib.DatastoreGet(UserDataStoreKey)
	if already_user {
		err = errors.New("Username already taken.")
		return

	}

	// Filling the user DS
	userdata.Username = username
	userdata.Password_hash = userlib.Argon2Key(password_bytes, nil, Password_key_length)
	userdata.File_meta_data_locator = nil
	userdata.Key = UserDataStoreKey

	// Generating RSA key
	key, err := userlib.GenerateRSAKey()
	if err != nil {
		err = errors.New("Error while InitUser")
		return
	}

	// Storing public key in key store
	userdata.PrivateKey = key
	pubkey := key.PublicKey
	userlib.KeystoreSet(username, pubkey)

	// Storing user data in User_Data_Store structure
	var userdatastore User_Data_Store
	Struct_JSON, json_err := json.Marshal(userdata)
	if json_err != nil {
		err = errors.New("")
		return
	}
	userdatastore.User_Data = Struct_JSON
	userdatamac := userlib.NewHMAC(userdata.Password_hash)
	userdatamac.Write(Struct_JSON)
	userdatastore.Content_hash = userdatamac.Sum(nil)
	User_Data_Store_JSON, user_data_json_err := json.Marshal(userdatastore)
	if user_data_json_err != nil {
		err = errors.New("Error while InitUser")
		return
	}

	// Encrypting the userdatastore and storing it in datastore
	// 1. Generating IV
	if len(UserDataStoreKeyBytes) < userlib.BlockSize {
		padding_length := userlib.BlockSize - len(UserDataStoreKeyBytes)
		padding := make([]byte, padding_length)
		UserDataStoreKeyBytes = append(UserDataStoreKeyBytes[:], padding[:]...)
	} else {
		UserDataStoreKeyBytes = UserDataStoreKeyBytes[:userlib.BlockSize]
	}

	// 2. Creating Cipher text
	ciphertext := make([]byte, userlib.BlockSize+len(User_Data_Store_JSON))
	copy(ciphertext[:userlib.BlockSize], userlib.RandomBytes(userlib.BlockSize))
	cipher := userlib.CFBEncrypter(userdata.Password_hash, ciphertext[:userlib.BlockSize])
	cipher.XORKeyStream(ciphertext[userlib.BlockSize:], User_Data_Store_JSON)
	userlib.DatastoreSet(UserDataStoreKey, ciphertext)

	return &userdata, err
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {

	// checking in Keystore if the user is present.
	_, is_user_present := userlib.KeystoreGet(username)
	if is_user_present == false {
		err = errors.New("Username or password is wrong")
		return
	}

	// Constructing the key to locate the user in the Data Store
	UserMetaData := username + password
	UserDataStoreKeyBytes := []byte(UserMetaData)
	password_bytes := []byte(password)
	mac := userlib.NewHMAC(password_bytes)
	mac.Write(UserDataStoreKeyBytes)
	UserDataStoreKeyBytes = mac.Sum(nil)
	UserDataStoreKey := hex.EncodeToString(UserDataStoreKeyBytes[:])
	Calculated_Password_hash := userlib.Argon2Key(password_bytes, nil, Password_key_length)

	// Checking if user is present and then loading the user data
	UserDataStoreValue, _ := userlib.DatastoreGet(UserDataStoreKey)
	if UserDataStoreValue == nil {
		err = errors.New("Username or password is wrong")
		return
	}

	// Decrypting from the DataStore
	// 1. Generating IV
	if len(UserDataStoreKeyBytes) < userlib.BlockSize {
		padding_length := userlib.BlockSize - len(UserDataStoreKeyBytes)
		padding := make([]byte, padding_length)
		UserDataStoreKeyBytes = append(UserDataStoreKeyBytes[:], padding[:]...)
	} else {
		UserDataStoreKeyBytes = UserDataStoreKeyBytes[:userlib.BlockSize]
	}

	// Decrypting the value obtained from Data Store Map

	if len(UserDataStoreValue) < userlib.BlockSize {
		err = errors.New("Data is corrupted")
		return nil, err
	}
	cipher := userlib.CFBDecrypter(Calculated_Password_hash, UserDataStoreValue[:userlib.BlockSize])
	cipher.XORKeyStream(UserDataStoreValue[userlib.BlockSize:], UserDataStoreValue[userlib.BlockSize:])

	// Unmarshaling to get in required struct format
	var UserDataStore User_Data_Store
	json_error := json.Unmarshal(UserDataStoreValue[userlib.BlockSize:], &UserDataStore)
	if json_error != nil {
		err = json_error
		return
	}

	// Checking integrity of the user data stored
	userdatamac := userlib.NewHMAC(Calculated_Password_hash)
	userdatamac.Write(UserDataStore.User_Data)
	Calculated_Content_hash := userdatamac.Sum(nil)

	if userlib.Equal(Calculated_Content_hash, UserDataStore.Content_hash) == false {
		err = errors.New("Data is corrupted")
		return
	}

	// Unmarshalling user data into user structure
	var userdata User
	json_error = json.Unmarshal(UserDataStore.User_Data, &userdata)
	if json_error != nil {
		err = errors.New("JSON Unmarshalling error")
		return
	}
	// Comparing K in (K,V)
	if strings.Compare(UserDataStoreKey, userdata.Key) != 0 {
		err = errors.New("Data is corrupted")
		return
	}

	// Verifying password is correct
	if userlib.Equal(Calculated_Password_hash, userdata.Password_hash) == false {
		err = errors.New("Data is corrupted")
		return
	}
	return &userdata, err
}

// This stores a file in the datastore.
//
// The name of the file should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {

	_ = userdata.UpdateUserStructure()
	if userdata.File_meta_data_locator == nil {
		userdata.File_meta_data_locator = make(map[string]File_Meta_Data_Locator)
	}

	// Searching if the user already has the file.
	_, file_present := userdata.File_meta_data_locator[filename]

	var NewFileMetaDataLocator File_Meta_Data_Locator
	var New_File_meta_data File_Meta_Data
	if file_present == true {
		NewFileMetaDataLocatorTemp, New_File_meta_data_temp, err := userdata.Get_File_Meta_Data(filename)
		if err != nil {
			// return
		}
		if New_File_meta_data_temp != nil {
			New_File_meta_data = *New_File_meta_data_temp
			err = userdata.DeleteFileParts(New_File_meta_data_temp)
			New_File_meta_data.FileParts_Map = make([]UUID_Hash_Pair, 0)
		}

		if err != nil {
			// return
		}
		NewFileMetaDataLocator = *NewFileMetaDataLocatorTemp

	} else {
		// New MetaData Locator to store metadata in map
		NewFileMetaDataLocator.File_UUID = GetUUID()
		NewFileMetaDataLocator.Encrypt_Key = userlib.RandomBytes(Encryption_Key_Size)

		// Store the new Metadata locatoe in Map of userdata
		userdata.File_meta_data_locator[filename] = NewFileMetaDataLocator
	}

	// Create new File meta data
	var New_UUID_hash_pair UUID_Hash_Pair
	New_UUID_hash_pair.File_Encrypt_Key = userlib.RandomBytes(Encryption_Key_Size)
	New_File_meta_data.File_Meta_Data_UUID = userdata.File_meta_data_locator[filename].File_UUID

	// New file part
	var NewFile_Part File_Part
	NewFile_Part.Content = data
	file_part_data_mac := userlib.NewHMAC(New_UUID_hash_pair.File_Encrypt_Key)
	file_part_data_mac.Write(NewFile_Part.Content)
	NewFile_Part.Content_Hash = file_part_data_mac.Sum(nil)

	JSON_File_Part, json_error := json.Marshal(NewFile_Part)
	if json_error != nil {

		return
	}

	// Encryption
	ciphertext := make([]byte, userlib.BlockSize+len(JSON_File_Part))
	copy(ciphertext[:userlib.BlockSize], userlib.RandomBytes(userlib.BlockSize))
	cipher := userlib.CFBEncrypter(New_UUID_hash_pair.File_Encrypt_Key, ciphertext[:userlib.BlockSize])
	cipher.XORKeyStream(ciphertext[userlib.BlockSize:], JSON_File_Part)

	file_part_UUID := GetUUID()
	userlib.DatastoreSet(file_part_UUID.String(), ciphertext)

	// To verify if Unmarshal is correct
	New_UUID_hash_pair.File_Part_UUID = file_part_UUID
	file_part_mac := userlib.NewHMAC(New_UUID_hash_pair.File_Encrypt_Key)
	file_part_mac.Write(ciphertext)
	New_UUID_hash_pair.File_Part_Hash = file_part_mac.Sum(nil)
	New_File_meta_data.FileParts_Map = append(New_File_meta_data.FileParts_Map, New_UUID_hash_pair)

	// Storing File metadata in DataStore
	var New_File_metadata_store File_Meta_Data_Store
	New_File_metadata_store.File_Meta_Data_JSON, json_error = json.Marshal(New_File_meta_data)
	if json_error != nil {
		return
	}
	file_metadata_mac := userlib.NewHMAC(NewFileMetaDataLocator.Encrypt_Key)
	file_metadata_mac.Write(New_File_metadata_store.File_Meta_Data_JSON)
	New_File_metadata_store.Content_Hash = file_metadata_mac.Sum(nil)
	JSON_File_metadata, json_error := json.Marshal(New_File_metadata_store)

	// Encryption
	ciphertext_file_metadata := make([]byte, userlib.BlockSize+len(JSON_File_metadata))
	copy(ciphertext_file_metadata[:userlib.BlockSize], userlib.RandomBytes(userlib.BlockSize))
	cipher_FM := userlib.CFBEncrypter(NewFileMetaDataLocator.Encrypt_Key, ciphertext_file_metadata[:userlib.BlockSize])
	cipher_FM.XORKeyStream(ciphertext_file_metadata[userlib.BlockSize:], JSON_File_metadata)
	userlib.DatastoreSet(New_File_meta_data.File_Meta_Data_UUID.String(), ciphertext_file_metadata)
	userdata.UpdateUser()
}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.

func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	userdata.UpdateUserStructure()
	FileMetaDataLocator, FileMetaData, err := userdata.Get_File_Meta_Data(filename)
	if err != nil {
		err = errors.New("Append Failed")
		return
	}

	err_helper := Append_helper(data, FileMetaDataLocator, FileMetaData)
	if err_helper != nil {
		err = errors.New("Append Failed")
	}
	return
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	userdata.UpdateUserStructure()
	// Check if file exists
	_, file_present := userdata.File_meta_data_locator[filename]
	if !file_present {
		return
	}

	// Loading Data from file metadata
	_, file_metadata_value, err_verify := userdata.Get_File_Meta_Data(filename)

	if err_verify != nil || file_metadata_value == nil {
		err = errors.New("Problem in loading file")
		err = err_verify
		return
	}
	var temp []byte
	for _, v := range file_metadata_value.FileParts_Map {
		file_part, valid := userlib.DatastoreGet(v.File_Part_UUID.String())
		if !valid {
			err = errors.New("Problem in loading file")
			return
		}
		if !userlib.Equal(GetHMAC(v.File_Encrypt_Key, file_part), v.File_Part_Hash) {
			err = errors.New("Problem in loading file")
			return
		}

		cipher := userlib.CFBDecrypter(v.File_Encrypt_Key, file_part[:userlib.BlockSize])
		if len(file_part) < userlib.BlockSize {
			err = errors.New("Data is corrupted")
			return nil, err
		}
		cipher.XORKeyStream(file_part[userlib.BlockSize:], file_part[userlib.BlockSize:])

		var to_read_data File_Part
		json_err := json.Unmarshal(file_part[userlib.BlockSize:], &to_read_data)
		if json_err != nil {
			err = errors.New("Problem in loading file")
			return
		}
		if !userlib.Equal(GetHMAC(v.File_Encrypt_Key, to_read_data.Content), to_read_data.Content_Hash) {
			err = errors.New("Problem in loading file")
			return
		}
		temp = append(temp[:], to_read_data.Content[:]...)
	}
	data = temp
	return
}

// You may want to define what you actually want to pass as a
// sharingRecord to serialized/deserialize in the data store.
type sharingRecord struct {
	Sharing_Message []byte
	Signature       []byte
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.

func (userdata *User) ShareFile(filename string, recipient string) (msgid string, err error) {
	userdata.UpdateUserStructure()
	RecipientPublicKey, is_user_present := userlib.KeystoreGet(recipient)
	if !is_user_present {
		err := errors.New("User not present")
		return "", err
	}

	FileMetaDataLocator, file_metadata_value, filemeta_err := userdata.Get_File_Meta_Data(filename)
	if filemeta_err != nil {
		return "", filemeta_err
	}

	for _, v := range file_metadata_value.FileParts_Map {
		is_valid, _ := ValidateFilePart(file_metadata_value, v)
		if !is_valid {
			err = errors.New("Problem in loading file")
			return
		}
	}

	EncryptedDataJSON, json_err := json.Marshal(FileMetaDataLocator)
	if json_err != nil {
		return "", filemeta_err
	}
	EncryptedData, encrypt_err := userlib.RSAEncrypt(&RecipientPublicKey, EncryptedDataJSON, []byte("Tag"))
	if encrypt_err != nil {
		return "", encrypt_err
	}

	SenderSign, ss_err := userlib.RSASign(userdata.PrivateKey, EncryptedDataJSON)
	if ss_err != nil {
		return "", json_err
	}

	var DataToShare sharingRecord
	DataToShare.Sharing_Message = EncryptedData
	DataToShare.Signature = SenderSign

	DataToShareJSON, json_err := json.Marshal(DataToShare)
	if json_err != nil {
		return "", json_err
	}
	msgid = hex.EncodeToString(DataToShareJSON)
	return msgid, nil

}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	msgid string) error {
	userdata.UpdateUserStructure()
	_, is_file_present := userdata.File_meta_data_locator[filename]
	if is_file_present {
		return errors.New("File already present. Cannot add new one ")
	}
	SenderPublicKey, is_user_present := userlib.KeystoreGet(sender)
	if !is_user_present {
		err := errors.New("Sender not present")
		return err
	}
	MsgSharedJSON, err := hex.DecodeString(msgid)
	if err != nil {
		return err
	}

	var DataToShare sharingRecord
	json_error := json.Unmarshal(MsgSharedJSON, &DataToShare)
	if json_error != nil {
		return json_error
	}

	DecryptedDataJSON, err := userlib.RSADecrypt(userdata.PrivateKey, DataToShare.Sharing_Message, []byte("Tag"))
	if err != nil {
		return err
	}

	err = userlib.RSAVerify(&SenderPublicKey, DecryptedDataJSON, DataToShare.Signature)
	if err != nil {
		return err
	}

	// Need to point to this address
	var FileMetaDataLocator File_Meta_Data_Locator
	json_error = json.Unmarshal(DecryptedDataJSON, &FileMetaDataLocator)
	if json_error != nil {
		return json_error
	}
	if userdata.File_meta_data_locator == nil {
		userdata.File_meta_data_locator = make(map[string]File_Meta_Data_Locator)
	}

	userdata.File_meta_data_locator[filename] = FileMetaDataLocator
	userdata.UpdateUser()
	return nil
}

// Removes access for all others.
func (userdata *User) RevokeFile(filename string) (err error) {
	userdata.UpdateUserStructure()
	// Searching if the user already has the file.
	_, file_present := userdata.File_meta_data_locator[filename]

	if !file_present {
		err = errors.New("Revoke File Failed")
		return
	}

	_, file_metadata_value, err_verify := userdata.Get_File_Meta_Data(filename)
	if err_verify != nil || file_metadata_value == nil {
		err = errors.New("Problem in loading file")
		err = err_verify
		return
	}

	userlib.DatastoreDelete(userdata.File_meta_data_locator[filename].File_UUID.String())

	// Remove MetaData Locator for the file in Map
	delete(userdata.File_meta_data_locator, filename)
	userdata.UpdateUser()
	for i, v := range file_metadata_value.FileParts_Map {

		is_valid, to_read_data := ValidateFilePart(file_metadata_value, v)
		if !is_valid {
			err = errors.New("Problem in loading file")
			return
		}
		userlib.DatastoreDelete(v.File_Part_UUID.String())
		if i == 0 {
			// If first entry into file
			userdata.StoreFile(filename, to_read_data.Content)
		} else {
			// New file exists so append to it
			err = userdata.AppendFile(filename, to_read_data.Content)
			if err != nil {
				return
			}
		}
	}
	userdata.UpdateUser()

	return
}

// Store Modified User Data Structure
func (userdata *User) UpdateUser() (err error) {
	// Searching if user name is occupied in Key Store
	_, already_user := userlib.KeystoreGet(userdata.Username)
	if already_user == false {
		err = errors.New("User not present")
		return
	}
	var userdatastore User_Data_Store
	Struct_JSON, json_err := json.Marshal(userdata)
	if json_err != nil {
		err = errors.New("JSON Marshalling error: User Meta data")
		return
	}

	userdatastore.User_Data = Struct_JSON
	userdatamac := userlib.NewHMAC(userdata.Password_hash)
	userdatamac.Write(Struct_JSON)
	userdatastore.Content_hash = userdatamac.Sum(nil)
	User_Data_Store_JSON, user_data_json_err := json.Marshal(userdatastore)
	if user_data_json_err != nil {
		err = errors.New("JSON Marshalling error: User Data store")
		return
	}
	UserDataStoreKeyBytes, decode_err := hex.DecodeString(userdata.Key)
	if decode_err != nil {
		err = decode_err
		return
	}
	// Encrypting the userdatastore and storing it in datastore
	// 1. Generating IV
	if len(UserDataStoreKeyBytes) < userlib.BlockSize {
		padding_length := userlib.BlockSize - len(UserDataStoreKeyBytes)
		padding := make([]byte, padding_length)
		UserDataStoreKeyBytes = append(UserDataStoreKeyBytes[:], padding[:]...)
	} else {
		UserDataStoreKeyBytes = UserDataStoreKeyBytes[:userlib.BlockSize]
	}

	// 2. Creating Cipher text
	ciphertext := make([]byte, userlib.BlockSize+len(User_Data_Store_JSON))
	copy(ciphertext[:userlib.BlockSize], userlib.RandomBytes(userlib.BlockSize))
	cipher := userlib.CFBEncrypter(userdata.Password_hash, ciphertext[:userlib.BlockSize])
	cipher.XORKeyStream(ciphertext[userlib.BlockSize:], User_Data_Store_JSON)
	userlib.DatastoreSet(userdata.Key, ciphertext)
	return
}

func GetHMAC(Key []byte, Data []byte) []byte {
	mac := userlib.NewHMAC(Key)
	mac.Write(Data)
	CalculatedHash := mac.Sum(nil)
	return CalculatedHash

}

func (userdata *User) Get_File_Meta_Data(filename string) (filemetadatalocator *File_Meta_Data_Locator, filemetadataptr *File_Meta_Data, err error) {
	// Searching if the user already has the file.
	FileMetaDataLocator, file_present := userdata.File_meta_data_locator[filename]
	filemetadatalocator = &FileMetaDataLocator

	if !file_present {
		err = errors.New("User does not contain file")
		return
	}
	// Getting the struct of the content + hash
	FileMetaDataStoreJSON, is_file_meta_data_present := userlib.DatastoreGet(FileMetaDataLocator.File_UUID.String())
	if !is_file_meta_data_present {
		err = errors.New("File Meta Data not present")
		return
	}

	// Decrypting the FileMetaDataStoreJSON into json format.
	if len(FileMetaDataStoreJSON) < userlib.BlockSize {
		err = errors.New("Data is corrupted")
		return
	}

	cipher := userlib.CFBDecrypter(FileMetaDataLocator.Encrypt_Key, FileMetaDataStoreJSON[:userlib.BlockSize])

	cipher.XORKeyStream(FileMetaDataStoreJSON[userlib.BlockSize:], FileMetaDataStoreJSON[userlib.BlockSize:])

	var FileMetaDataStore File_Meta_Data_Store

	json_error := json.Unmarshal(FileMetaDataStoreJSON[userlib.BlockSize:], &FileMetaDataStore)
	if json_error != nil {
		err = errors.New("JSON Unmarshalling failed1 ")
		return
	}

	Calculated_Hash_File_Meta_Data := GetHMAC(FileMetaDataLocator.Encrypt_Key, FileMetaDataStore.File_Meta_Data_JSON)
	if userlib.Equal(Calculated_Hash_File_Meta_Data, FileMetaDataStore.Content_Hash) == false {
		err = errors.New("Data corrupted1")
		return
	}

	// Unmarshalling to get the file meta data.
	var FileMetaData File_Meta_Data
	json_error = json.Unmarshal(FileMetaDataStore.File_Meta_Data_JSON, &FileMetaData)
	if json_error != nil {
		err = errors.New("JSON Unmarshalling failed2 ")
		return
	}

	// Compare that UUID is same
	if !userlib.Equal([]byte(FileMetaDataLocator.File_UUID.String()), []byte(FileMetaData.File_Meta_Data_UUID.String())) {
		err = errors.New("Data corrupted2")
		return
	}

	return &FileMetaDataLocator, &FileMetaData, nil
}

func GetUUID() (newuuidptr uuid.UUID) {
	found := false
	var NewUUID uuid.UUID
	for !found {
		NewUUID = bytesToUUID(userlib.RandomBytes(FileUUIDLength))
		_, is_slot_full := userlib.DatastoreGet(NewUUID.String())
		if !is_slot_full {
			found = true
		}
	}
	return NewUUID
}

func ValidateFilePart(file_metadata_value *File_Meta_Data, v UUID_Hash_Pair) (ret bool, to_read_data File_Part) {
	ret = false
	file_part, valid := userlib.DatastoreGet(v.File_Part_UUID.String())
	if !valid {
		// err = errors.New("Problem in loading file")
		return
	}

	if !userlib.Equal(GetHMAC(v.File_Encrypt_Key, file_part), v.File_Part_Hash) {
		// err = errors.New("Problem in loading file")
		return
	}

	cipher := userlib.CFBDecrypter(v.File_Encrypt_Key, file_part[:userlib.BlockSize])

	cipher.XORKeyStream(file_part[userlib.BlockSize:], file_part[userlib.BlockSize:])

	json_err := json.Unmarshal(file_part[userlib.BlockSize:], &to_read_data)
	if json_err != nil {
		// err = errors.New("Problem in loading file")
		return
	}
	if !userlib.Equal(GetHMAC(v.File_Encrypt_Key, to_read_data.Content), to_read_data.Content_Hash) {
		// err = errors.New("Problem in loading file")
		return
	}
	ret = true
	return
}

func Append_helper(data []byte, FileMetaDataLocator *File_Meta_Data_Locator, FileMetaData *File_Meta_Data) (err error) {
	var NewFile_Part File_Part
	var New_UUID_hash_pair UUID_Hash_Pair
	New_UUID_hash_pair.File_Encrypt_Key = userlib.RandomBytes(Encryption_Key_Size)
	NewFile_Part.Content = data
	file_part_data_mac := userlib.NewHMAC(New_UUID_hash_pair.File_Encrypt_Key)
	file_part_data_mac.Write(NewFile_Part.Content)
	NewFile_Part.Content_Hash = file_part_data_mac.Sum(nil)

	JSON_File_Part, json_error := json.Marshal(NewFile_Part)
	if json_error != nil {
		err = json_error
		return
	}

	// Encrypting the content and the hash of the file block
	ciphertext := make([]byte, userlib.BlockSize+len(JSON_File_Part))
	copy(ciphertext[:userlib.BlockSize], userlib.RandomBytes(userlib.BlockSize))
	cipher := userlib.CFBEncrypter(New_UUID_hash_pair.File_Encrypt_Key, ciphertext[:userlib.BlockSize])
	cipher.XORKeyStream(ciphertext[userlib.BlockSize:], JSON_File_Part)

	file_part_UUID := GetUUID()
	userlib.DatastoreSet(file_part_UUID.String(), ciphertext)

	New_UUID_hash_pair.File_Part_UUID = file_part_UUID
	file_part_mac := userlib.NewHMAC(New_UUID_hash_pair.File_Encrypt_Key)
	file_part_mac.Write(ciphertext)
	New_UUID_hash_pair.File_Part_Hash = file_part_mac.Sum(nil)
	FileMetaData.FileParts_Map = append(FileMetaData.FileParts_Map, New_UUID_hash_pair)

	// Converting file meta data into json
	var FileMetaDataStore File_Meta_Data_Store
	FileMetaDataStore.File_Meta_Data_JSON, json_error = json.Marshal(FileMetaData)
	if json_error != nil {
		err = json_error
		return
	}
	file_metadata_mac := userlib.NewHMAC(FileMetaDataLocator.Encrypt_Key)
	file_metadata_mac.Write(FileMetaDataStore.File_Meta_Data_JSON)
	FileMetaDataStore.Content_Hash = file_metadata_mac.Sum(nil)
	FileMetaDataStoreData, json_error := json.Marshal(FileMetaDataStore)

	if json_error != nil {
		err = errors.New("JSON Unmarshalling error")
		return
	}

	// Encryption
	ciphertext_file_metadata := make([]byte, userlib.BlockSize+len(FileMetaDataStoreData))
	copy(ciphertext_file_metadata[:userlib.BlockSize], userlib.RandomBytes(userlib.BlockSize))
	cipher_FM := userlib.CFBEncrypter(FileMetaDataLocator.Encrypt_Key, ciphertext_file_metadata[:userlib.BlockSize])
	cipher_FM.XORKeyStream(ciphertext_file_metadata[userlib.BlockSize:], FileMetaDataStoreData)
	userlib.DatastoreSet(FileMetaData.File_Meta_Data_UUID.String(), ciphertext_file_metadata)
	return
}

func (userdata *User) UpdateUserStructure() (err error) {

	// Constructing the key to locate the user in the Data Store
	UserDataStoreKeyBytes, decode_err := hex.DecodeString(userdata.Key)
	if decode_err != nil {
		err = decode_err
		return
	}

	UserDataStoreKey := hex.EncodeToString(UserDataStoreKeyBytes[:])

	// Checking if user is present and then loading the user data
	UserDataStoreValue, _ := userlib.DatastoreGet(UserDataStoreKey)
	if UserDataStoreValue == nil {
		err = errors.New("Username or password is wrong")
		return
	}

	// Decrypting from the DataStore
	// 1. Generating IV
	if len(UserDataStoreKeyBytes) < userlib.BlockSize {
		padding_length := userlib.BlockSize - len(UserDataStoreKeyBytes)
		padding := make([]byte, padding_length)
		UserDataStoreKeyBytes = append(UserDataStoreKeyBytes[:], padding[:]...)
	} else {
		UserDataStoreKeyBytes = UserDataStoreKeyBytes[:userlib.BlockSize]
	}

	// Decrypting the value obtained from Data Store Map
	if len(UserDataStoreValue) < userlib.BlockSize {
		err = errors.New("Data is corrupted")
		return
	}
	cipher := userlib.CFBDecrypter(userdata.Password_hash, UserDataStoreValue[:userlib.BlockSize])
	cipher.XORKeyStream(UserDataStoreValue[userlib.BlockSize:], UserDataStoreValue[userlib.BlockSize:])

	// Unmarshaling to get in required struct format
	var UserDataStore User_Data_Store
	json_error := json.Unmarshal(UserDataStoreValue[userlib.BlockSize:], &UserDataStore)
	if json_error != nil {
		err = json_error
		return
	}

	// Checking integrity of the user data stored
	userdatamac := userlib.NewHMAC(userdata.Password_hash)
	userdatamac.Write(UserDataStore.User_Data)
	Calculated_Content_hash := userdatamac.Sum(nil)

	if userlib.Equal(Calculated_Content_hash, UserDataStore.Content_hash) == false {
		err = errors.New("Data is corrupted")
		return
	}

	// Unmarshalling user data into user structure
	json_error = json.Unmarshal(UserDataStore.User_Data, &userdata)
	if json_error != nil {
		err = errors.New("JSON Unmarshalling error")
		return
	}
	// Comparing K in (K,V)
	if strings.Compare(UserDataStoreKey, userdata.Key) != 0 {
		err = errors.New("Data is corrupted")
		return
	}

	return
}

func (userdata *User) DeleteFileParts(file_metadata_value *File_Meta_Data) (err error) {
	for _, v := range file_metadata_value.FileParts_Map {
		userlib.DatastoreDelete(v.File_Part_UUID.String())
	}
	return
}
