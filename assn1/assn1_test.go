package assn1

import "github.com/fenilfadadu/CS628-assn1/userlib"
import "testing"
import "strings"
import "reflect"
import "fmt"
import "encoding/hex"

// You can actually import other stuff if you want IN YOUR TEST
// HARNESS ONLY.  Note that this is NOT considered part of your
// solution, but is how you make sure your solution is correct.

func TestInit(t *testing.T) {
	t.Log("Initialization test")
	userlib.DebugPrint = true
	//	someUsefulThings()

	//userlib.DebugPrint = false
	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
	}
	// t.Log() only produces output if you run with "go test -v"
	t.Log("Got user", u)
	// You probably want many more tests here.
}

func TestInitUser(t *testing.T) {

	//Normal InitUser scenario
	_, err := InitUser("bob", "foobar")
	if err != nil {
		t.Error("Failed to initialize user bob", err)
	}

	//Scenario where InitUser is called with existing username in the key store.
	_, err = InitUser("bob", "foobar")
	if err == nil {
		t.Error("Creating  account with already existing username", err)
	}
}

func TestGetUser(t *testing.T) {
	//Scenario where user is not present in the data store and GetUser is performed
	user, err := GetUser("bob1", "fubar")
	if err == nil {
		t.Error("Loaded unsaved user from Data Store", err)
	}

	//Scenario where password is wrong.
	user, err = GetUser("bob", "fubar")
	if err == nil {
		t.Error("Loading user is successful for wrong password", err)
	}

	//Scenario where GetUser is successful
	user, err = GetUser("bob", "foobar")
	if err != nil {
		t.Error("Loading User failed", err)
	}

	if strings.Compare(user.Username, "bob") != 0 {
		t.Error("Incorrect data retrieved")
	}

	// Scenario where Data is corrupted and GetUser is performed

	username := "corrupted_user"
	password := "fu"
	user, err = InitUser(username, password)
	if err != nil {
		t.Error("Init user failed for\n user:", username, "password:", password, "\n Error:", err)
	}

	UserMetaData := username + password
	UserDataStoreKeyBytes := []byte(UserMetaData)
	password_bytes := []byte(password)
	mac := userlib.NewHMAC(password_bytes)
	mac.Write(UserDataStoreKeyBytes)
	UserDataStoreKeyBytes = mac.Sum(nil)
	UserDataStoreKey := hex.EncodeToString(UserDataStoreKeyBytes[:])
	rewrite_data := "abcd"
	corrupted_data := []byte(rewrite_data)
	userlib.DatastoreSet(UserDataStoreKey, corrupted_data)

	user, err = GetUser(username, password)
	if err == nil {
		t.Error("Loaded corrupted data from Data Store", err, len(corrupted_data))
	}

	// Scenario where user details are delted from the data store
	userlib.DatastoreDelete(UserDataStoreKey)
	user, err = GetUser(username, password)
	if err == nil {
		t.Error("Loaded corrupted data from Data Store", err)
	}
}

func TestUpdateUser(t *testing.T) {

	//Scenario where Update User Data is Sucessful
	user, err := GetUser("bob", "foobar")
	if err != nil {
		t.Error("Loading User failed", err)
	}

	user.File_meta_data_locator = nil
	err = user.UpdateUser()

	user, err = GetUser("bob", "foobar")
	if err != nil {
		t.Error("Loading User failed", err)
	}

	if user.File_meta_data_locator != nil {
		t.Error("User user failed", err)

	}

}

func TestStorage(t *testing.T) {
	fmt.Println("Testing storage")
	// And some more tests, because
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}
	t.Log("Loaded user", u)

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	if u.File_meta_data_locator != nil {
		_, is_present := u.File_meta_data_locator["file1"]
		if !is_present {
			t.Error("File Store failed", err)
		}
	}

	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
	}
	t.Log("The contents of file loaded is ", string(v2[:]))
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
	}

	// Scenario where store file is called on the file which is already present.

	v = []byte("This is a second test")
	u.StoreFile("file1", v)

	v2, err2 = u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
	}
	t.Log("The contents of file loaded is ", string(v2[:]))
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
	}

	//fmt.Println("Calling Revoke here")
	_ = u.RevokeFile("file1")

	//fmt.Println("----------------------------Calling Load File here")

	v2, err2 = u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
	}
	t.Log(v2)
}

func TestAppend(t *testing.T) {
	user, err := GetUser("bob", "foobar")
	if err != nil {
		t.Error("Loading User failed", err)
	}
	// 1. Requesting to Append to a  file which is not present under user.
	filename := "abcdef"
	str := "This is a test"
	str_bytes := []byte(str)
	err = user.AppendFile(filename, str_bytes)
	if err == nil {
		t.Error("Append file is sucesssful for a file which is not present ")
	}
	// 2. Requesting to update a valid file

	user.StoreFile(filename, str_bytes)
	Loaded_File, Loaded_Error := user.LoadFile(filename)
	if Loaded_Error != nil {
		t.Error("Load file failed ")
	}
	Loaded_File_str := string(Loaded_File[:])

	if strings.Compare(str, Loaded_File_str) != 0 {
		t.Error("File stored and loaded are different")

	}
	append_str := " Echo!"
	modified_string := str + append_str
	append_str_bytes := []byte(append_str)
	append_err := user.AppendFile(filename, append_str_bytes)
	if append_err != nil {
		t.Error("AppendFile failed ")
	}

	append_str = "\nNew Data Coming!! Embrace"
	modified_string = modified_string + append_str
	append_str_bytes = []byte(append_str)
	append_err = user.AppendFile(filename, append_str_bytes)
	if append_err != nil {
		t.Error("AppendFile failed ")
	}

	Loaded_File, Loaded_Error = user.LoadFile(filename)
	if Loaded_Error != nil {
		t.Error("Load file failed after Appending")
	}
	Loaded_File_str = string(Loaded_File[:])

	if strings.Compare(Loaded_File_str, modified_string) != 0 {
		t.Error("File append is wrong")

	}

	_ = user.RevokeFile(filename)
	Loaded_File, Loaded_Error = user.LoadFile(filename)
	if Loaded_Error != nil {
		t.Error("Load file failed after Appending")
	}
	Loaded_File_str = string(Loaded_File[:])
	fmt.Println("Read After Revoke :\n" + Loaded_File_str)

}

func TestShare(t *testing.T) {
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
	}
	u2, err2 := InitUser("charlie", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize charlie", err2)
	}

	var msgid string

	v, err := u.LoadFile("file1")

	if err != nil {
		t.Error("Failed to download the file from alice", err)
	}

	msgid, err = u.ShareFile("file1", "charlie")
	if err != nil {
		t.Error("Failed to share the a file", err)
	}
	err = u2.ReceiveFile("file2", "alice", msgid)
	if err != nil {
		t.Error("Failed to receive the share message", err)
	}

	v2, err := u2.LoadFile("file2")

	if err != nil {
		t.Error("Failed to download the file after sharing", err)
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
	}
}

func TestRevoke(t *testing.T) {
	append_str := "Hello World!!"
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
	}
	u2, err2 := GetUser("charlie", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize charlie", err2)
	}
	a_data, err := u.LoadFile("file1")
	if err != nil {
		t.Error("Load Failed")
	}
	new_data := append(a_data[:], []byte(append_str)[:]...)
	u2.AppendFile("file2", []byte(append_str))

	a_app_data, err := u.LoadFile("file1")
	if err != nil {
		t.Error("Load Failed")
	}

	if !reflect.DeepEqual(new_data, a_app_data) {
		t.Error("File data different")
	}
	// fmt.Println(string(a_app_data[:]), "\n"+string(new_data[:]))
	err = u2.RevokeFile("file2")
	if err != nil {
		t.Error(err)
	}
	a_data, err = u.LoadFile("file1")
	if err == nil {
		t.Error(string(a_data[:]))
	}

	a_app_data, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Load Failed")
	}
	fmt.Println(string(a_app_data[:]), "\n"+string(a_data[:]))

	str := "This is a test"
	str_bytes := []byte(str)
	filename := "testingrevoke"

	u.StoreFile(filename, str_bytes)
	msgid, err := u.ShareFile(filename, "charlie")
	if err != nil {
		t.Error("Failed to share the a file", err)
	}
	err = u2.ReceiveFile(filename, "alice", msgid)
	if err != nil {
		t.Error("Failed to receive the share message", err)
	}
	err = u.RevokeFile(filename)
	if err != nil {
		t.Error(err)
	}
	err = u2.RevokeFile(filename)
	if err == nil {
		t.Error(err)
	}
}

func TestSingleUserMultipleInstances(t *testing.T) {
	//Normal InitUser scenario
	user1, err := InitUser("user1", "foobar")
	if err != nil {
		t.Error("Failed to initialize user bob", err)
	}
	user2, err := GetUser("user1", "foobar")
	if err != nil {
		t.Error("Loading User failed", err)
	}
	filename := "abcdef"
	str := "This is a test"
	str_bytes := []byte(str)

	str2 := "This is not a test"
	str_bytes2 := []byte(str2)

	user1.StoreFile(filename, str_bytes)

	// Checking if the file has been updated for single user instance.
	Loaded_File, Loaded_Error := user2.LoadFile(filename)
	if Loaded_Error != nil {
		t.Error("Load file failed ")
	}
	Loaded_File_str := string(Loaded_File[:])
	if strings.Compare(str, Loaded_File_str) != 0 {
		t.Error("File stored and loaded are different")

	}

	// Test case to check if store on same file is working.
	user2.StoreFile(filename, str_bytes2)
	Loaded_File, Loaded_Error = user2.LoadFile(filename)
	if Loaded_Error != nil {
		t.Error("Load file failed ")
	}
	Loaded_File_str2 := string(Loaded_File[:])

	if strings.Compare(str2, Loaded_File_str2) != 0 {
		t.Error("File stored and loaded are different\n Expected:", str2, " \n Actual:", Loaded_File_str2)

	}
}

func TestIntegTests(t *testing.T) {

	/*
		* Scenario where
			1. User1 has file file1 stored and shared with user2
			2. User2 has file file1 received from user1 and stored under file2
			3. File Meta Data has been mutated.
			4. User1 calls load file.
			5. User2 calls store file
			6. User1 loads the file.
			7. File Data has been mutated.
			8. User1 revokes file.
			9. User2 loads file
	*/
	username1 := "donald"
	password1 := "duck"
	user1, err := InitUser(username1, password1)
	if err != nil {
		t.Error("Failed to initialize user ", username1, err)
	}
	username2 := "popoye"
	password2 := "sailor man"
	user2, err := InitUser(username2, password2)
	if err != nil {
		t.Error("Failed to initialize user ", username2, err)
	}

	str1 := "This is a test"
	str2 := "This is also a test"

	filename := "file1"
	filename2 := "file2"

	file1 := []byte(str1)
	file2 := []byte(str2)
	user1.StoreFile(filename, file1)

	msgid, err := user1.ShareFile(filename, username2)
	if err != nil {
		t.Error("Failed to share the a file", err)
	}
	err = user2.ReceiveFile(filename2, username1, msgid)
	if err != nil {
		t.Error("Failed to receive the share message", err)
	}
	user2.StoreFile(filename2, file2)

	loaded_file, err := user1.LoadFile(filename)
	if err != nil {
		t.Error("Failed to upload and download", err)
	}
	loaded_file_str := string(loaded_file[:])
	if strings.Compare(str2, loaded_file_str) != 0 {
		t.Error("File stored and loaded are different\n Expected:", str2, " \n Actual:", loaded_file_str)

	}

	// 3. Mutating the meta data
	file_meta_data := user2.File_meta_data_locator[filename2]
	corrupted_data := "abcd"
	corrupted_data_bytes := []byte(corrupted_data)
	userlib.DatastoreSet(file_meta_data.File_UUID.String(), corrupted_data_bytes)
	loaded_file, err = user1.LoadFile(filename)
	if err == nil {
		t.Error("Loaded corrupted file", err)
	}
	user2.StoreFile(filename2, file1)
	loaded_file, err = user1.LoadFile(filename)
	if err != nil {
		t.Error("Loaded corrupted file", err)
	}
	loaded_file_str = string(loaded_file[:])

	if strings.Compare(str1, loaded_file_str) != 0 {
		t.Error("File stored and loaded are different\n Expected:", str1, " \n Actual:", loaded_file_str)

	}

	// Mutating file data
	_, file_metadata_value, _ := user1.Get_File_Meta_Data(filename)
	corrupted_data = "abcd"
	corrupted_data_bytes = []byte(corrupted_data)

	t.Log(file_metadata_value)
	userlib.DatastoreSet(file_metadata_value.FileParts_Map[0].File_Part_UUID.String(), corrupted_data_bytes)
	_ = user1.RevokeFile(filename)
	loaded_file, err = user2.LoadFile(filename2)
	if err == nil {
		t.Error("Loaded corrupted file", err)
	}
}
func TestGetIV(t *testing.T) {
	/*uuid := GetUUID()
	random_bytes := userlib.RandomBytes(userlib.BlockSize)

	iv := GetIV(uuid, random_bytes)
	fmt.Println(iv)
	n := 1
	var test string = string(n)
	var temp int = strconv.Ito}*/
}
