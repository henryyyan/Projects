package client_test

// You MUST NOT change these default imports.  ANY additional imports may
// break the autograder and everyone will be sad.

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.
	_ "encoding/hex"
	_ "errors"
	_ "strconv"
	_ "strings"
	"testing"

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect().
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	"github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
}

// ================================================
// Global Variables (feel free to add more!)
// ================================================
const defaultPassword = "password"
const emptyString = ""
const contentOne = "Bitcoin is Nick's favorite "
const contentTwo = "digital "
const contentThree = "cryptocurrency!"

// ================================================
// Describe(...) blocks help you organize your tests
// into functional categories. They can be nested into
// a tree-like structure.
// ================================================

var _ = Describe("Client Tests", func() {

	// A few user declarations that may be used for testing. Remember to initialize these before you
	// attempt to use them!
	var alice *client.User
	var bob *client.User
	var charles *client.User
	var doris *client.User
	var eve *client.User
	// var frank *client.User
	// var grace *client.User
	// var horace *client.User
	// var ira *client.User

	// These declarations may be useful for multi-session testing.
	var alicePhone *client.User
	var aliceLaptop *client.User
	var aliceDesktop *client.User
	var bobLaptop *client.User

	var err error

	// A bunch of filenames that may be useful.
	aliceFile := "aliceFile.txt"
	bobFile := "bobFile.txt"
	charlesFile := "charlesFile.txt"
	// dorisFile := "dorisFile.txt"
	// eveFile := "eveFile.txt"
	// frankFile := "frankFile.txt"
	// graceFile := "graceFile.txt"
	// horaceFile := "horaceFile.txt"
	// iraFile := "iraFile.txt"

	BeforeEach(func() {
		// This runs before each test within this Describe block (including nested tests).
		// Here, we reset the state of Datastore and Keystore so that tests do not interfere with each other.
		// We also initialize
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	Describe("Basic Tests", func() {

		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Basic Test: Testing Single User Store/Load/Append.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Revoke Functionality", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

	})

	Specify("Our test", func() {
		userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
		alice, err = client.InitUser("alice", defaultPassword)
		Expect(err).To(BeNil())

		bob, err = client.InitUser("bob", defaultPassword)
		Expect(err).To(BeNil())

		charles, err = client.InitUser("charles", defaultPassword)
		Expect(err).To(BeNil())

		_, err := client.GetUser("alice", defaultPassword + "1")
		Expect(err).ToNot(BeNil()) // (error) Get Alice user using wrong password

		_, err = client.GetUser("alice", defaultPassword)
		Expect(err).To(BeNil()) // (works) Get Alice user using correct password


		// Specify("Our test: Try making another user with username alice", func {
		// 	userlib.DebugMsg("Try making another user with username alice")
		// 	_, err = client.InitUser("alice", defaultPassword)
		// 	Expect(err).ToNot(BeNil())

		// 	_, err = client.InitUser("alice", defaultPassword + "1")
		// 	Expect(err).ToNot(BeNil())
		// })

		userlib.DebugMsg("Try making another user with username alice")
		_, err = client.InitUser("alice", defaultPassword)
		Expect(err).ToNot(BeNil())
		_, err = client.InitUser("alice", defaultPassword + "1")
		Expect(err).ToNot(BeNil())

		_, err = client.InitUser("alicepas", "sword")
		Expect(err).To(BeNil())


		userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
		err = alice.StoreFile(aliceFile, []byte(contentOne))
		Expect(err).To(BeNil())

		userlib.DebugMsg("Bob creating a file with the same name")
		err = bob.StoreFile(aliceFile, []byte(contentTwo))
		Expect(err).To(BeNil()) // should be no error

		userlib.DebugMsg("Alice creating file with same name (different content)")
		err = alice.StoreFile(aliceFile, []byte(contentTwo))
		Expect(err).To(BeNil())

		userlib.DebugMsg("Alice creating file with same name (different content)")
		err = alice.StoreFile(aliceFile, []byte(contentTwo))
		Expect(err).To(BeNil())

		userlib.DebugMsg("Checking that Alice can still load the file.")
		data, err := alice.LoadFile(aliceFile)
		Expect(err).To(BeNil())
		Expect(data).To(Equal([]byte(contentTwo)))

		userlib.DebugMsg("Alice setback aliceFile to contentOne")
		err = alice.StoreFile(aliceFile, []byte(contentOne))
		Expect(err).To(BeNil())

		userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

		invite1, err := alice.CreateInvitation(aliceFile, "bob")
		Expect(err).To(BeNil())

		err = bob.AppendToFile(aliceFile, []byte(contentOne))
		Expect(err).To(BeNil()) // Bob appending contentOne to aliceFIle

		// check that it appended to his aliceFile, and not Alice's aliceFile
		data, err = alice.LoadFile(aliceFile)
		Expect(err).To(BeNil())
		Expect(data).To(Equal([]byte(contentOne)))

		data, err = bob.LoadFile(aliceFile)
		Expect(err).To(BeNil())
		Expect(data).To(Equal([]byte(contentTwo + contentOne)))

		err = bob.AcceptInvitation("alice", invite1, aliceFile)
		Expect(err).ToNot(BeNil()) // (error) Bob accepting invite but reusing a filename

		err = bob.AcceptInvitation("charles", invite1, bobFile)
		Expect(err).ToNot(BeNil()) // (error) Bob accepting invite from wrong sender

		err = bob.AcceptInvitation("alice", invite1, bobFile)
		Expect(err).To(BeNil()) // (works) Bob accepting invite1 from Alice
		
		userlib.DebugMsg("Accept twice (same name)")
		err = bob.AcceptInvitation("alice", invite1, bobFile)
		Expect(err).ToNot(BeNil()) // error accepting again

		userlib.DebugMsg("Accept twice (different name)")
		err = bob.AcceptInvitation("alice", invite1, bobFile + "1")
		Expect(err).ToNot(BeNil()) // error accepting again

		userlib.DebugMsg("Checking that Alice can still load the file.")
		data, err = alice.LoadFile(aliceFile)
		Expect(err).To(BeNil())
		Expect(data).To(Equal([]byte(contentOne)))

		userlib.DebugMsg("Checking that Bob can still load his aliceFile.")
		data, err = bob.LoadFile(aliceFile)
		Expect(err).To(BeNil())
		Expect(data).To(Equal([]byte(contentTwo + contentOne)))

		userlib.DebugMsg("Alice loading file using Bob's name for the file (Alice does not have this file)")
		_, err = alice.LoadFile(bobFile)
		Expect(err).ToNot(BeNil()) // error

		_, err = charles.LoadFile(aliceFile)
		Expect(err).ToNot(BeNil()) // error charles does not have access to aliceFile

		err = charles.AppendToFile(aliceFile, []byte("xd"))
		Expect(err).ToNot(BeNil()) // error charles does not have access to aliceFile

		err = charles.RevokeAccess(aliceFile, "alice")
		Expect(err).ToNot(BeNil()) // error charles is not owner (also does not have access) to aliceFile

		// bob tries to revoke access for bobFile
		err = bob.RevokeAccess(bobFile, "alice")
		Expect(err).ToNot(BeNil()) // try to revoke owner (Alice) access from what Bob calls bobFile, alice calls this aliceFile

		err = bob.RevokeAccess(bobFile, "charles")
		Expect(err).ToNot(BeNil()) // try to revoke owner (Alice) access from what Bob calls bobFile, alice calls this aliceFile
	})
	

	Specify("Our second test", func() {
		
		userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
		alice, err = client.InitUser("alice", defaultPassword)
		Expect(err).To(BeNil())

		bob, err = client.InitUser("bob", defaultPassword)
		Expect(err).To(BeNil())

		charles, err = client.InitUser("charles", defaultPassword)
		Expect(err).To(BeNil())

		doris, err = client.InitUser("doris", defaultPassword)
		Expect(err).To(BeNil())

		eve, err = client.InitUser("eve", defaultPassword)
		Expect(err).To(BeNil())

		userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
		err = alice.StoreFile(aliceFile, []byte(contentOne))
		Expect(err).To(BeNil())

		userlib.DebugMsg("Alice storing file %s with content: %s", bobFile, contentTwo)
		err = bob.StoreFile(bobFile, []byte(contentTwo))
		Expect(err).To(BeNil())

		invite1, err := alice.CreateInvitation(aliceFile, "bob")
		Expect(err).To(BeNil())

		invite4, err := alice.CreateInvitation(aliceFile, "eve")
		Expect(err).To(BeNil())

		err = eve.AcceptInvitation("alice", invite4, aliceFile)
		Expect(err).To(BeNil())

		err = bob.AppendToFile(aliceFile, []byte("bob"))
		Expect(err).ToNot(BeNil())

		// revoking before accepted
		err = alice.RevokeAccess(aliceFile, "bob") 
		Expect(err).To(BeNil()) // (works) alice should be able to revoke before bob accepts

		err = bob.AcceptInvitation("alice", invite1, aliceFile)
		Expect(err).ToNot(BeNil()) // (error) bob cannot accepted revoked invPtr from alice

		invite1, err = alice.CreateInvitation(aliceFile, "bob")
		Expect(err).To(BeNil()) // reshare invPtr invite1 to bob

		err = bob.AcceptInvitation("charles", invite1, aliceFile)
		Expect(err).ToNot(BeNil()) // (error) bob tires to accept from wrong sender name

		err = bob.AcceptInvitation("alice", invite1, bobFile)
		Expect(err).ToNot(BeNil()) // (error) bob tries to accept invitation and call the shared file bobFile, which he already has

		// err = charles.AcceptInvitation("alice", invite1, bobFile)
		// Expect(err).ToNot(BeNil()) // (error) charles to accept bob's invitationPtr

		err = bob.AcceptInvitation("alice", invite1, aliceFile)
		Expect(err).To(BeNil())

		_, err = bob.CreateInvitation(aliceFile, "dog")
		Expect(err).ToNot(BeNil()) // (error) creating invitation for someone who doesn't exist

		invite2, err := bob.CreateInvitation(aliceFile, "charles")
		Expect(err).To(BeNil())

		invite3, err := bob.CreateInvitation(aliceFile, "doris")
		Expect(err).To(BeNil())

		err = charles.AcceptInvitation("bob", invite2, aliceFile)
		Expect(err).To(BeNil())

		err = doris.AcceptInvitation("bob", invite2, aliceFile)
		Expect(err).ToNot(BeNil()) // (error) doris accepted charles's invitation pointer that charles has already accepted

		err = doris.AcceptInvitation("bob", invite3, aliceFile)
		Expect(err).To(BeNil())

		err = bob.AppendToFile(aliceFile, []byte("bob"))
		Expect(err).To(BeNil()) // (works) bob will append "bob" to the file

		err = charles.AppendToFile(aliceFile, []byte("charles"))
		Expect(err).To(BeNil()) // (works) charles will append "charles" to the file

		content, err := alice.LoadFile(aliceFile)
		Expect(err).To(BeNil())
		Expect(content).To(Equal([]byte(contentOne + "bob" + "charles")))

		content, err = bob.LoadFile(aliceFile)
		Expect(err).To(BeNil())
		Expect(content).To(Equal([]byte(contentOne + "bob" + "charles")))

		content, err = charles.LoadFile(aliceFile)
		Expect(err).To(BeNil())
		Expect(content).To(Equal([]byte(contentOne + "bob" + "charles")))

		content, err = eve.LoadFile(aliceFile)
		Expect(err).To(BeNil())
		Expect(content).To(Equal([]byte(contentOne + "bob" + "charles")))

		err = alice.RevokeAccess(aliceFile, "charles")
		Expect(err).ToNot(BeNil()) // (error) alice cannot revoke charles, as bob -> charles

		err = alice.RevokeAccess(aliceFile, "bob")
		Expect(err).To(BeNil()) // (works) alice revokes bob, should also revoke charles

		err = alice.RevokeAccess(aliceFile, "bob")
		Expect(err).ToNot(BeNil()) // (error) alice revokes bob again

		err = bob.AppendToFile(aliceFile, []byte("bob"))
		Expect(err).ToNot(BeNil()) // (error) bob cannot append to aliceFile after revoke

		err = charles.AppendToFile(aliceFile, []byte("charles"))
		Expect(err).ToNot(BeNil()) // (error) charles cannot append to aliceFile after revoke

		err = doris.AppendToFile(aliceFile, []byte("doris"))
		Expect(err).ToNot(BeNil()) // (error) doris cannot append to aliceFile after revoke

		err = eve.AppendToFile(aliceFile, []byte("eve"))
		Expect(err).To(BeNil()) // (works) eve can append to aliceFile after revoke called on bob

		_, err = bob.LoadFile(aliceFile)
		Expect(err).ToNot(BeNil()) // (error) bob cannot load aliceFile after revoke

		_, err = charles.LoadFile(aliceFile)
		Expect(err).ToNot(BeNil()) // (error) charles cannot load aliceFile after revoke

		_, err = doris.LoadFile(aliceFile)
		Expect(err).ToNot(BeNil()) // (error) doris cannot load aliceFile after revoke

		// content, err = eve.LoadFile(aliceFile)
		// Expect(err).To(BeNil())
		// Expect(content).To(Equal([]byte(contentOne + "bob" + "charles" + "eve")))

		content, err = alice.LoadFile(aliceFile)
		Expect(err).To(BeNil())
		Expect(content).To(Equal([]byte(contentOne + "bob" + "charles" + "eve")))
	})

	Specify("Multi-device testing", func() {
		alice, err = client.InitUser("alice", defaultPassword)
		Expect(err).To(BeNil())

		bob, err = client.InitUser("bob", defaultPassword)
		Expect(err).To(BeNil())

		aliceLaptop, err = client.GetUser("alice", defaultPassword)
		Expect(err).To(BeNil())

		bobLaptop, err = client.GetUser("bob", defaultPassword)
		Expect(err).To(BeNil())

		// alicePhone, err = client.GetUser("alice", defaultPassword)
		// Expect(err).To(BeNil())

		err = alice.StoreFile(aliceFile, []byte(contentOne))
        Expect(err).To(BeNil())

		invite1, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
        Expect(err).To(BeNil())

		err = bob.AcceptInvitation("alice", invite1, aliceFile)
        Expect(err).To(BeNil())

		err = alice.AppendToFile(aliceFile, []byte("alice"))
        Expect(err).To(BeNil())

		err = aliceLaptop.AppendToFile(aliceFile, []byte("alice"))
        Expect(err).To(BeNil())

		data, err := alice.LoadFile(aliceFile)
		Expect(err).To(BeNil())
		Expect(data).To(Equal([]byte(contentOne + "alice" + "alice")))

		data, err = aliceLaptop.LoadFile(aliceFile)
		Expect(err).To(BeNil())
		Expect(data).To(Equal([]byte(contentOne + "alice" + "alice")))

		data, err = bob.LoadFile(aliceFile)
		Expect(err).To(BeNil())
		Expect(data).To(Equal([]byte(contentOne + "alice" + "alice")))

		data, err = bobLaptop.LoadFile(aliceFile)
		Expect(err).To(BeNil())
		Expect(data).To(Equal([]byte(contentOne + "alice" + "alice")))

		err = aliceLaptop.RevokeAccess(aliceFile, "bob")
		Expect(err).To(BeNil())

		err = alice.RevokeAccess(aliceFile, "bob")
		Expect(err).ToNot(BeNil())

		_, err = bobLaptop.LoadFile(aliceFile)
		Expect(err).ToNot(BeNil())

		_, err = bob.LoadFile(aliceFile)
		Expect(err).ToNot(BeNil())
	})

	// measureBandwidth := func(probe func()) (bandwidth int) {
	// 	before := userlib.DatastoreGetBandwidth()
	// 	probe()
	// 	after := userlib.DatastoreGetBandwidth()
	// 	return after - before
	//  }
	 
	//  // Example usage
	//  bw = measureBandwidth(func() {
	// 	alice.StoreFile(...)
	//  })

	//  Specify("Bandwidth test")


})
