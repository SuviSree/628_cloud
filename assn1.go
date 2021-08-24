package assn1

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.
//
import (

	// You neet to add with
	// go get github.com/sarkarbidya/CS628-assn1/userlib

	"github.com/sarkarbidya/CS628-assn1/userlib"

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
	// test
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

var configBlockSize = 4096 //Do not modify this variable

//setBlockSize - sets the global variable denoting blocksize to the passed parameter. This will be called only once in the beginning of the execution
func setBlockSize(blocksize int) {
	configBlockSize = blocksize
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

//User : User structure used to store the user information
type User struct {
	Username string
	//Password      string
	DatastoreKey  []byte
	RsaprivateKey *userlib.PrivateKey
	HmacKey       []byte
	CFBKey        []byte
	FileKeys      map[string][]byte
	//RsaprivateKey []byte
	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

type FileMetadata struct {
	FileId         string
	HmacKey        []byte
	FileEncryptKey []byte
	Offset         int
	Datablocks     map[string][]byte
}

// StoreFile : function used to create a  file
// It should store the file in blocks only if length
// of data []byte is a multiple of the blocksize; if
// this is not the case, StoreFile should return an error.
func (userdata *User) StoreFile(filename string, data []byte) (err error) {
	var metadata FileMetadata
	if len(data)%configBlockSize != 0 {
		return errors.New("data not in terms of block size")
	}
	//check for the empty filename
	if filename == "" {
		errors.New("empty filename not allowed please enter some valid filename")
	}
	//check whether the file is already present with the mentioned filename
	_, dupFile := userdata.FileKeys[filename]
	if !dupFile {
		errors.New("mentioned filename already exist")
	}
	//check for the zero filesize
	if len(data) == 0 {
		errors.New("Empty file not alllowed")
	}
	metadata.FileId = uuid.New().String()
	metadata.Datablocks = make(map[string][]byte)
	metadata.Offset = 0
	metadata.HmacKey = userlib.Argon2Key([]byte(filename), userlib.RandomBytes(16), uint32(userlib.AESKeySize))
	metadata.FileEncryptKey = userlib.Argon2Key([]byte(filename), userlib.RandomBytes(16), uint32(userlib.AESKeySize))
	//metadata.DataBlockKey = userlib.Argon2Key([]byte(filename), salt, uint32(userlib.AESKeySize))

	//file blockkey will be uuid + offset number using salt as UUID of file
	offset, _ := json.Marshal(metadata.Offset)
	blockKey := metadata.FileId + string(offset)
	dataBlockKey := userlib.Argon2Key([]byte(blockKey), userlib.RandomBytes(16), uint32(userlib.AESKeySize))

	//encypting and hashing datablock to be stored

	enData := MyCFBencrypter(metadata.FileEncryptKey, data)
	dataMac := MyHmacGenerator(metadata.HmacKey, enData)

	datastream := append(enData, dataMac...)
	//storing offset as index of Datablock map

	metadata.Datablocks[string(offset)] = dataBlockKey
	//metadata.Datablocks[strconv.Itoa(0)] = dataBlockKey            //storing the hashed data into Datablock
	userlib.DatastoreSet(string(dataBlockKey), []byte(datastream)) //storing ecvrypt+map of data in datastore

	//fileMetadata storage Key
	metadataKey := userlib.Argon2Key([]byte(userdata.Username+filename), userlib.RandomBytes(16), 2*uint32(userlib.AESKeySize))
	metaencryptKey := metadataKey[uint32(userlib.AESKeySize):]
	metaHmacKey := metadataKey[:uint32(userlib.AESKeySize)]
	//encrypt filemetadata and store

	fileMetaMarshalled, _ := json.Marshal(metadata)

	//encrypt +mac fileMetadata
	enfileMetadata := MyCFBencrypter(metaencryptKey, fileMetaMarshalled)
	fileMetaMac := MyHmacGenerator(metaHmacKey, enfileMetadata)

	filemetaStream := append(enfileMetadata, fileMetaMac...)
	//storing file metadata in Datastore
	userlib.DatastoreSet(string(metadataKey), filemetaStream)
	//saving the metadatalocation corresponding to the file name
	userdata.FileKeys = make(map[string][]byte)
	userdata.FileKeys[filename] = metadataKey

	return err
}

//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need. The length of data []byte must be a multiple of
// the block size; if it is not, AppendFile must return an error.
// AppendFile : Function to append the file
func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	var metadata FileMetadata
	if len(data)%configBlockSize != 0 {
		return errors.New("data not in terms of block size")
	}
	//check for the zero data size
	if len(data) == 0 {
		return errors.New("there is no data to be appended")
	}
	//metadataKey := metadataKey := userlib.Argon2Key([]byte(userdata.Username+filename), userlib.RandomBytes(16), uint32(userlib.AESKeySize))
	//check whether the file metadata is corrupted..Intigrity check
	metadataKey, validfile := userdata.FileKeys[filename]

	//check if filenamae is invalid
	if metadataKey == nil {
		return errors.New("Invalid file name")
	}
	if !validfile {
		return errors.New("file doesn't exist")
	}

	metaencryptKey := metadataKey[uint32(userlib.AESKeySize):]
	metaHmacKey := metadataKey[:uint32(userlib.AESKeySize)]

	//check for the valid file name
	metadataMarshalled, ok := userlib.DatastoreGet(string(metadataKey))
	if !ok {
		errors.New("Invalid File Name")
	}
	receivedMetadata := metadataMarshalled[:(len(metadataMarshalled) - userlib.HashSize)]
	receivedMac := metadataMarshalled[(len(metadataMarshalled) - userlib.HashSize):]

	calculatedMac := MyHmacGenerator(metaHmacKey, receivedMetadata)

	if !userlib.Equal(receivedMac, calculatedMac) {
		return errors.New("Metadata of file is corrupted .Intigrity of the data is compromised")
	}
	marshalledMetadata := Decrypter(metaencryptKey, receivedMetadata)
	if err := json.Unmarshal(marshalledMetadata, &metadata); err != nil {
		errors.New("Metadata Unmarshal Failed")
	}
	//increment the offset by one
	metadata.Offset = metadata.Offset + 1
	//encrypt and hash data ..then store it to datastore .............................................
	offset, _ := json.Marshal(metadata.Offset)
	blockKey := metadata.FileId + string(offset)
	//blockKey := metadata.FileId + strconv.Itoa(metadata.Offset)
	dataBlockKey := userlib.Argon2Key([]byte(blockKey), userlib.RandomBytes(16), uint32(userlib.AESKeySize))

	//encypting and hashing datablock to be stored

	enData := MyCFBencrypter(metadata.FileEncryptKey, data)
	dataMac := MyHmacGenerator(metadata.HmacKey, enData)

	datastream := append(enData, dataMac...)
	//storing offset as index of Datablock map
	metadata.Datablocks[string(offset)] = dataBlockKey             //storing the hashed data into Datablock
	userlib.DatastoreSet(string(dataBlockKey), []byte(datastream)) //storing ecvrypt+map of data in datastore
	//-------------------------------------------------------------------------------------------------------------
	//encrypt and hash the file metadata as we have made the changes to the file metadata
	fileMetaMarshalled, _ := json.Marshal(metadata)

	//encrypt +mac fileMetadata
	enfileMetadata := MyCFBencrypter(metaencryptKey, fileMetaMarshalled)
	fileMetaMac := MyHmacGenerator(metaHmacKey, enfileMetadata)

	filemetaStream := append(enfileMetadata, fileMetaMac...)
	//storing file metadata in Datastore
	userlib.DatastoreSet(string(metadataKey), filemetaStream)
	//-------------------------------------------------------------------------------------------------------------
	return err
}

// LoadFile :This loads a block from a file in the Datastore.
//
// It should give an error if the file block is corrupted in any way.
// If there is no error, it must return exactly one block (of length blocksize)
// of data.
//
// LoadFile is also expected to be efficient. Reading a random block from the
// file should not fetch more than O(1) blocks from the Datastore.
func (userdata *User) LoadFile(filename string, offset int) (data []byte, err error) {
		var metadata FileMetadata

	//metadataKey := metadataKey := userlib.Argon2Key([]byte(userdata.Username+filename), userlib.RandomBytes(16), uint32(userlib.AESKeySize))
	metadataKey := userdata.FileKeys[filename]
        if metadataKey == nil {
		return nil, errors.New("Invalid file name")
	}
	metaencryptKey := metadataKey[uint32(userlib.AESKeySize):]
	metaHmacKey := metadataKey[:uint32(userlib.AESKeySize)]

	metadataMarshalled, ok := userlib.DatastoreGet(string(metadataKey))
	if !ok {
		//return nil,errors.New("Invalid File Name")
		err = errors.New("Error")
	}
	/*
		receivedMetadata, receivedMac := MyCFBdecrypter(metaencryptKey, metadataMarshalled)

		calculatedMac := MyHmacGenerator(metaHmacKey, receivedMetadata)
	*/
	//fmt.Println("calculated Mac : ", string(calculatedMac))

	receivedMetadata := metadataMarshalled[:(len(metadataMarshalled) - userlib.HashSize)]
	receivedMac := metadataMarshalled[(len(metadataMarshalled) - userlib.HashSize):]

	calculatedMac := MyHmacGenerator(metaHmacKey, receivedMetadata)

	if !userlib.Equal(receivedMac, calculatedMac) {
		//return nil, errors.New("Metadata of file is corrupted .Intigrity of the data is compromised")
		err = errors.New("Error")
	}
	marshalledMetadata := Decrypter(metaencryptKey, receivedMetadata)
	if err := json.Unmarshal(marshalledMetadata, &metadata); err != nil {
		//return nil, errors.New("Metadata Unmarshal Failed")
		err = errors.New("Error")
	}
	if metadata.Offset < offset {
		return nil, errors.New("Out of bound offset")
	}
	//fmt.Println("offset inside loadfile : ", metadata.Offset)
	//blockKey := metadata.FileId + strconv.Itoa(offset)
	//dataBlockKey := string(userlib.Argon2Key([]byte(blockKey), []byte(metadata.FileId), uint32(userlib.AESKeySize)))
	marshalledOffset, _ := json.Marshal(offset)
	data, success := userlib.DatastoreGet(string(metadata.Datablocks[string(marshalledOffset)]))
	if !success {
		//return nil, errors.New("Mentioned offset is out of bound")
		err = errors.New("Error")
	}
	//check mac and decrypt the stored data at the mentioned datablock
	receiveddata := data[:(len(data) - userlib.HashSize)]
	receiveddataMac := data[(len(data) - userlib.HashSize):]

	calculateddataMac := MyHmacGenerator(metadata.HmacKey, receiveddata)

	if !userlib.Equal(receiveddataMac, calculateddataMac) {
		//return nil, errors.New("Data is corrupted..Integrity of data is compromised")
		err = errors.New("Error")
	}
	plaintext := Decrypter(metadata.FileEncryptKey, receiveddata)

	return plaintext, err													
}

// ShareFile : Function used to the share file with other user
func (userdata *User) ShareFile(filename string, recipient string) (msgid string, err error) {

	//check for empty filename or recipient name
	if filename == "" || recipient == "" {
		return "", errors.New("Empty file name or recipient name")
	}
	var sharing sharingRecord
	recPubKey, ok := userlib.KeystoreGet(recipient)
	//check for the valid recipient name
	if !ok {
		return "", errors.New("Invalid Recipient Name")
	}
	filelocation, filecheck := userdata.FileKeys[filename]
	//check for the valid filename
	if !filecheck {
		return "", errors.New("Invalid filename")
	}
	ecnrMetalocation, ok2 := userlib.RSAEncrypt(&recPubKey, filelocation, []byte("filesharing"))
	if ok2 != nil {
		return "", errors.New("Error while ecryption")
	}

	rsaSign, ok1 := userlib.RSASign(userdata.RsaprivateKey, filelocation)

	if ok1 != nil {
		return "", errors.New("Error in signing the data")
	}

	sharing.EncrMetaLocation = ecnrMetalocation
	sharing.RsaSignature = rsaSign

	marshalled, ok3 := json.Marshal(sharing)
	if ok3 != nil {
		return "", errors.New("Error while Marshalling the sharing data record")
	}
	msgId := string(marshalled)

	//userlib.DatastoreSet(msgId, marshalled)

	return msgId, err

}

// ReceiveFile:Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
// ReceiveFile : function used to receive the file details from the sender
func (userdata *User) ReceiveFile(filename string, sender string, msgid string) error {
	if filename == "" || sender == "" {
		errors.New("Empty filename or sender")
	}
	_, dupFile := userdata.FileKeys[filename]
	if !dupFile {
		errors.New("file already exists")
	}
	senderPubKey, ok := userlib.KeystoreGet(sender)

	if !ok {
		return errors.New("Invalid Sender")
	}

	//getting shared rec by unmarshalling the marshalled data
	var sharedRec sharingRecord
	err := json.Unmarshal([]byte(msgid), &sharedRec)
	if err != nil {
		errors.New("Error while unmarshalling")
	}

	//decrypting the locaitondetails  and then verifying it with rsa signature
	fileMetaLocation, err := userlib.RSADecrypt(userdata.RsaprivateKey, []byte(sharedRec.EncrMetaLocation), []byte("filesharing"))
	if err != nil {
		errors.New("Error while decripting")
	}

	err = userlib.RSAVerify(&senderPubKey, fileMetaLocation, []byte(sharedRec.RsaSignature))

	if err != nil {
		return errors.New("Invalid signature")
	}

	userdata.FileKeys[filename] = fileMetaLocation

	return err
}

// RevokeFile : function used revoke the shared file access
func (userdata *User) RevokeFile(filename string) (err error) {
	var metadata FileMetadata
	var newMetadata FileMetadata
	metadataKey := userdata.FileKeys[filename]
	oldKey := metadataKey
	metaencryptKey := metadataKey[uint32(userlib.AESKeySize):]
	metaHmacKey := metadataKey[:uint32(userlib.AESKeySize)]
	//fmt.Println("Old metadatakey : ", string(metadataKey))
	//check for the valid file name
	metadataMarshalled, ok := userlib.DatastoreGet(string(metadataKey))
	if !ok {
		errors.New("Invalid File Name")
	}
	receivedMetadata := metadataMarshalled[:(len(metadataMarshalled) - userlib.HashSize)]
	receivedMac := metadataMarshalled[(len(metadataMarshalled) - userlib.HashSize):]

	calculatedMac := MyHmacGenerator(metaHmacKey, receivedMetadata)

	if !userlib.Equal(receivedMac, calculatedMac) {
		errors.New("Metadata of file is corrupted .Intigrity of the data is compromised")
	}
	marshalledMetadata := Decrypter(metaencryptKey, receivedMetadata)
	if err := json.Unmarshal(marshalledMetadata, &metadata); err != nil {
		errors.New("Metadata Unmarshal Failed")
	}

	//fmt.Println("inside revoke Number of Offset : ", metadata.Offset)
	newFileId := uuid.New().String()
	//metadata.Datablocks = make(map[string][]byte)
	newHmacKey := userlib.Argon2Key([]byte(filename), userlib.RandomBytes(16), uint32(userlib.AESKeySize))
	newFileEncryptKey := userlib.Argon2Key([]byte(filename), userlib.RandomBytes(16), uint32(userlib.AESKeySize))

	//new Metadata Details
	newMetadata.FileId = newFileId
	newMetadata.Datablocks = make(map[string][]byte)
	newMetadata.Offset = metadata.Offset
	newMetadata.HmacKey = newHmacKey
	newMetadata.FileEncryptKey = newFileEncryptKey
	for i := 0; i <= metadata.Offset; i++ {
		offset, _ := json.Marshal(metadata.Offset)
		data, _ := userlib.DatastoreGet(string(metadata.Datablocks[string(offset)]))

		receiveddata := data[:(len(data) - userlib.HashSize)]
		receiveddataMac := data[(len(data) - userlib.HashSize):]

		calculateddataMac := MyHmacGenerator(metadata.HmacKey, receiveddata)

		if !userlib.Equal(receiveddataMac, calculateddataMac) {
			return errors.New("Data is corrupted..Integrity of data is compromised")
		}
		plaintext := Decrypter(metadata.FileEncryptKey, receiveddata)
		blockKey := newFileId + string(offset)
		dataBlockKey := userlib.Argon2Key([]byte(blockKey), userlib.RandomBytes(16), uint32(userlib.AESKeySize))

		//encypting and hashing datablock to be stored

		enData := MyCFBencrypter(newFileEncryptKey, plaintext)
		dataMac := MyHmacGenerator(newHmacKey, enData)

		datastream := append(enData, dataMac...)
		//storing offset as index of Datablock map
		newMetadata.Datablocks[string(offset)] = dataBlockKey

		//metadata.Datablocks[string(offset)] = dataBlockKey //storing the hashed data into Datablock
		userlib.DatastoreSet(string(dataBlockKey), []byte(datastream))

	}

	//file blockkey will be uuid + offset number using salt as UUID of file
	//offset, _ := json.Marshal(metadata.Offset)
	marshalledMetadata, _ = json.Marshal(newMetadata)
	//generating new metadatakey to hash and encrypt the filemetadata to new key ..which will lead to change in location of file metadata in datastore
	metadataKey = userlib.Argon2Key([]byte(userdata.Username+filename), userlib.RandomBytes(16), 2*uint32(userlib.AESKeySize))
	metaencryptKey = metadataKey[uint32(userlib.AESKeySize):]
	metaHmacKey = metadataKey[:uint32(userlib.AESKeySize)]
	//fmt.Println("New MetadataKey : ", string(metadataKey))
	//encypt and hash metadata with new key
	enfileMetadata := MyCFBencrypter(metaencryptKey, marshalledMetadata)
	fileMetaMac := MyHmacGenerator(metaHmacKey, enfileMetadata)

	filemetaStream := append(enfileMetadata, fileMetaMac...)
	//storing file metadata in Datastore
	userlib.DatastoreSet(string(metadataKey), filemetaStream)
	//saving the new metadatalocation corresponding to the file name
	userdata.FileKeys[filename] = metadataKey
	userlib.DatastoreDelete(string(oldKey))
	return err
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.
// You may want to define what you actually want to pass as a
// sharingRecord to serialized/deserialize in the data store.
type sharingRecord struct {
	EncrMetaLocation []byte
	RsaSignature     []byte
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

//InitUser : function used to create user
func InitUser(username string, password string) (userdataptr *User, err error) {
	var user User
	//checking for empty username or password
	if username == "" || password == "" {
		errors.New("Username or password cannot be empty string")
	}
	//check for the duplicate username.
	_, okUser := userlib.KeystoreGet(username)
	if okUser {
		errors.New("Username taken please choose different username")
	}

	salt := []byte(username)
	user.FileKeys = make(map[string][]byte)
	user.Username = username

	user.DatastoreKey = userlib.Argon2Key([]byte(password), salt, uint32(len(username)))
	user.HmacKey = userlib.Argon2Key([]byte(password), salt, uint32(2*userlib.AESKeySize))
	user.RsaprivateKey, _ = userlib.GenerateRSAKey()
	PublicKey := user.RsaprivateKey.PublicKey
	user.CFBKey = userlib.Argon2Key([]byte(password), salt, uint32(userlib.BlockSize))

	userMarshalled, err := json.Marshal(user)

	euserdata := make([]byte, userlib.BlockSize+len(userMarshalled))
	iv := euserdata[:userlib.BlockSize]
	copy(iv, userlib.RandomBytes(userlib.BlockSize))
	encryptor := userlib.CFBEncrypter(user.CFBKey, iv)
	encryptor.XORKeyStream(euserdata[userlib.BlockSize:], userMarshalled)

	//generate HMAC
	mac := userlib.NewHMAC(user.HmacKey)
	mac.Write(euserdata)
	hmac := mac.Sum(nil)

	HmacCyphertext := append(euserdata, hmac...)

	userlib.DatastoreSet(string(user.DatastoreKey), HmacCyphertext)
	userlib.KeystoreSet(username, PublicKey)

	return &user, err
}

// GetUser : This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
//GetUser : function used to get the user details
func GetUser(username string, password string) (userdataptr *User, err error) {
	var user User
	//validate user from keystore
	_, okUser := userlib.KeystoreGet(username)
	if !okUser {
		return nil, errors.New("user not found in keystore")
	}

	salt := []byte(username)
	DSkeycheck := userlib.Argon2Key([]byte(password), salt, uint32(len(username)))
	user.HmacKey = userlib.Argon2Key([]byte(password), salt, uint32(2*userlib.AESKeySize))
	user.CFBKey = userlib.Argon2Key([]byte(password), salt, uint32(userlib.BlockSize))
	//getting user from datastore
	HmacCyphertext, ok := userlib.DatastoreGet(string(DSkeycheck))
	if !ok {
		return nil, errors.New("Incorrect Password Entered")
	}

	euserdata := HmacCyphertext[:(len(HmacCyphertext) - userlib.HashSize)]
	Recievedhmac := HmacCyphertext[(len(HmacCyphertext) - userlib.HashSize):]

	hmac := MyHmacGenerator(user.HmacKey, euserdata)
	marshalleduserdata := Decrypter(user.CFBKey, euserdata)

	if !userlib.Equal(hmac, Recievedhmac) {
		return nil, errors.New("IntegrityError: Data is Corrupted")
	}

	//MyCFBdecrypter(user.CFBKey, euserdata)
	if err := json.Unmarshal(marshalleduserdata, &user); err != nil {
		err = errors.New("Shared Key Unmarshal Failed")
	}

	//fmt.Println("Inside Get user :", string(user.Username))
	return &user, err
}
func MyCFBencrypter(key []byte, data []byte) []byte {
	ciphertext := make([]byte, userlib.BlockSize+len(data))
	iv := ciphertext[:userlib.BlockSize]
	copy(iv, userlib.RandomBytes(userlib.BlockSize))
	stream := userlib.CFBEncrypter(key, iv)
	stream.XORKeyStream(ciphertext[userlib.BlockSize:], data)
	return ciphertext
}
func Decrypter(key []byte, data []byte) []byte {
	iv := data[:userlib.BlockSize]
	decryptor := userlib.CFBDecrypter(key, iv)
	ciphertext := data[userlib.BlockSize:]
	decryptor.XORKeyStream(ciphertext, ciphertext)
	return ciphertext
}

func MyHmacGenerator(key []byte, data []byte) []byte {
	mac := userlib.NewHMAC(key)
	mac.Write(data)
	hmac := mac.Sum(nil)

	return hmac
}
