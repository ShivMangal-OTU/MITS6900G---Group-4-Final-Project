# Blockchain Final Project 
# Group 4
# By: Isabella Smith (100749097), Julia Smith (100749753), Shiv Mangal (100550777)

# Import Statements
import json
import hashlib
from time import time
from flask import Flask, render_template, request
from uuid import uuid4
import webbrowser
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization


# EMRBlock class is our blockchain object
class EMRBlock(object):
    # The mining difficulty level
    difficulty = "000"

    # EMRBlockchain initializer
    # chain: a list of information related to each block on the blockchain
    # currentVist: a list of patient information to be turned into a block and appended to the chain
    # genesisHash: the genesis hash of the blockchain
    # Initializes the first block in the blockchain
    def __init__(self):
        self.chain = []
        self.currentVisit = []
        genesisHash = self.blockHash("")
        self.appendBlock(hash_of_previous_block = genesisHash, nonce = self.PoW(0, genesisHash, []))
        
    # blockHash function
    # This function creates a hash of a block of information
    # Input: a block of information
    # Output: the sha256 hash of the block
    def blockHash(self, block):
        # JSON.dumps converts the python object into JSON Strings
        blockEncoder = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(blockEncoder).hexdigest()
    
    # Proof of Work Function
    # This function finds the nonce of the block (mining the block)
    # Input: block index, hash of the previous block, and transaction list
    # Output: the nonce of the block that validates it
    def PoW(self, index, hash_of_previous_block, transactions):
        nonce = 0
        while self.validateProof(index, hash_of_previous_block, transactions, nonce) is False:
            nonce +=1
        return nonce
    
    # Validate proof function
    # This function checks if the given nonce validates the block
    # A nonce validates the block if the hash of the block with the nonce begins with the amount of 0's in the difficulty level
    # Input: block index, hash of the previous block, transaction list, and nonce to try
    # Output: returns True if the nonce validates the block; returns False if the nonce does not validate the block
    def validateProof(self, index, hash_of_previous_block, visits, nonce):
        data = f'{index},{hash_of_previous_block},{visits},{nonce}'.encode()
        hash_data = hashlib.sha256(data).hexdigest()
        return hash_data[:len(self.difficulty)] == self.difficulty
    
    # Append block function
    # This function creates a block and appends the block to the blockchain
    # After the block is created, it makes current visit empty because the vists have now been added to the blockchain
    # Input: nonce, hash of the previous block
    # Output: the block containing all the visit information
    def appendBlock(self, nonce, hash_of_previous_block):
        block = {
            'index': len(self.chain),
            'visits': self.currentVisit,
            'timestamp':time(),
            'nonce':nonce,
            'hash_of_previous_block': hash_of_previous_block
            }
        self.currentVisit = []
        self.chain.append(block)
        return block
    
    # Add visit function
    # Appends visit information to the currentVisit list
    # When a block is created, the information in currentVisit will be turned into a block before being set back to empty
    # Input: various medical information
    # Output: returns the length of the blockchain
    def addVisit(self, date, aptTime, symptoms, diagnosis, test, treatment, medication, followUp, addNotes):
        self.currentVisit.append({
            'Date':date,
            'Time':aptTime,
            'Symptoms':symptoms,
            'Diagnosis':diagnosis,
            'Test':test,
            'Treatment':treatment,
            'Medication':medication,
            'Follow Up':followUp,
            'Additional Notes':addNotes
        })
        return self.lastBlock['index']+1
    
    # Add first visit function
    # Appends visit information related to the patient's first visit to the currentVisit list
    # When a block is created, the information in currentVisit will be turned into a block before being set back to empty
    # Input: various medical information
    # Output: returns the length of the blockchain
    def firstVisit(self, publicKey, firstName, lastName, gender, birthDate, nationality, martialStatus, address, phoneNumber, email, allergies, medicalHistory, emergeContact):
        self.currentVisit.append({
            'Patient Public Key':publicKey,
            'First Name':firstName,
            'Last Name':lastName,
            'Gender':gender,
            'Birth Date':birthDate,
            'Nationality':nationality,
            'Martial Status':martialStatus,
            'Address':address,
            'Phone Number':phoneNumber,
            'Email Address':email,
            'Allergies':allergies,
            'Medicial History':medicalHistory,
            'Emergency Contact':emergeContact
        })
        return self.lastBlock['index']+1

    @property
    def lastBlock(self):
        return self.chain[-1]
    

# Test Functions
app = Flask(__name__)

node_identifier = str(uuid4()).replace("-", "")
blockchain = EMRBlock()

#Displays the html page "index.html" when you click the button to go to the home page
@app.route('/home')
def index():
    print("Home Page")
    return render_template("index.html", name="home")

#Displays the html page "blockchain.html" when you click the button to view the blockchain
@app.route('/block', methods=['GET'])
def full_chain():
    print("Blockchain")
    response = {
        'chain':blockchain.chain,
        'length':str(len(blockchain.chain))
        }
    return render_template("blockchain.html", data=response)
   # return jsonify(response), 200

# Displays the html page "keypair.html" when you click the button to generate a key pair
# NOTE: The keys generated are for display purposes only. Due to limitations within the webbrowser library
# used for this project, we could not use Javascript to generate a digital signature using the key generated in
# this step. See line 252 for more information on how we implemented digital signatures.
@app.route('/keypair', methods=['GET','POST'])
def keyPair():
    print("Key Pair")
    private = ""
    public = ""
    
    # Uses a password to generate a key - this password is used to seralize the key (and is also needed for deserialization)
    if request.method == "POST":
        password = request.form.get("password")
        password = password.encode()
        
        # Generate Private Key
        # https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
        privateGen = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private = privateGen.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password)
        )
        # Derive Public Key from Private Key
        public = privateGen.public_key().public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        
        # Remove Headers in the key it generates
        public = public.decode()
        public = public.replace("-----BEGIN PUBLIC KEY-----", "")
        public = public.replace("-----END PUBLIC KEY-----", "")
        public = public.strip()
    
        private = private.decode()
        private = private.replace("-----BEGIN ENCRYPTED PRIVATE KEY-----", "")
        private = private.replace("-----END ENCRYPTED PRIVATE KEY-----", "")
        private = private.strip()
    
    # Display the keys on the web page
    return render_template("keypair.html", public=public, private = private)

# Displays the html page "newpatient.html" when you click the button to register a new person
@app.route('/firstvisit', methods=['GET', 'POST'])
def newPatient():
    print("New Patient")
    if request.method == "POST":
        key = request.form.get("key")
        first = request.form.get("first")
        last = request.form.get("last")
        gender = request.form.get("gender")
        birth = request.form.get("birth")
        nationality = request.form.get("nationality")
        status = request.form.get("status")
        address = request.form.get("address")
        number = request.form.get("number")
        email = request.form.get("email")
        allergies = request.form.get("allergies")
        history = request.form.get("history")
        emergency = request.form.get("emergency")
        blockchain.firstVisit(key, first, last, gender, birth, nationality, status, address, number, email, allergies, history, emergency)
        response = {'message': f'Transaction will be added to the block'}
        
        # adds the block to the blockchain
        lastBlockHash = blockchain.blockHash(blockchain.lastBlock)
        index = len(blockchain.chain)
        nonce = blockchain.PoW(index,lastBlockHash,blockchain.currentVisit)
        block = blockchain.appendBlock(nonce,lastBlockHash)
        response = {
            'Message': f'Transaction added to block {index}',
            'Hash of Previous Block': block['hash_of_previous_block'],
            'Nonce':block['nonce'],
            'visits':block['visits']}
    return render_template("newpatient.html")

# Displays the html page "patientvisit.html" when you click the button to record a new visit by a patient
@app.route('/patientvisit', methods=['GET','POST'])
def patientVisit():
    print("Patient Visit")
    returnSign = ""
    status = ""
    if request.method == "POST":
        date = request.form.get("date")
        time = request.form.get("time")
        symptoms = request.form.get("symptoms")
        diagnosis = request.form.get("diagnosis")
        test = request.form.get("test")
        treatment = request.form.get("treatment")
        medication = request.form.get("medication")
        follow = request.form.get("follow")
        notes = request.form.get("notes")
        blockchain.addVisit(date, time, symptoms, diagnosis, test, treatment, medication, follow, notes)
        response = {'message': f'Transaction will be added to the block'}
        
        # Adds the visit as a transaction to the block
        lastBlockHash = blockchain.blockHash(blockchain.lastBlock)
        index = len(blockchain.chain)
        nonce = blockchain.PoW(index,lastBlockHash,blockchain.currentVisit)
        block = blockchain.appendBlock(nonce,lastBlockHash)
        response = {
            'Message': f'Transaction added to block {index}',
            'Hash of Previous Block': block['hash_of_previous_block'],
            'Nonce':block['nonce'],
            'visits':block['visits']}
        
        # Signing the Message and Verifying the Digital Signature
        # NOTE: This implementation is digital signatures is meant to showcase how digital signatures would
        # be implemented in a real EMR blockchain application. Ideally, you would want to use the keys generated
        # in the key pair generation step, but due to library limitations within our project, this was not possible.
        # Alternatively, we implemented digital signatures using a separate key generated for the purpose of this demonstration.
        
        # The message we are signing is all the information included in the transaction concatenated
        # Need to encode it because the message must be a byte string
        message = (date + time + symptoms + diagnosis + test + treatment + medication + follow + notes).encode()
        
        # Generates a new private key without a password
        privateKey = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Derives the public key from the private key
        publicKey = privateKey.public_key()
        
        # Signs the message using the private key
        # This operation provides security, since only the owner of the private key can verify the signature
        signature = privateKey.sign(
            message,
            padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256())
        
        # Verifies that the signature is correct by verifying it using the person's private key
        # Ideally, the person filling out the form on the page will enter their private key into the first input box
        # then that private key will be used to verify the signature that was computed using the person's public key
        # (since the public key is public and can be seen by everyone)
        # We wanted to make it so if the signature verification failed (meaning the private key entered was not correct)
        # the form would not submit, and it would display an error. However, this is not possible without using Javascript,
        # so we hardcoded an example here
        
        #NOTE: using the following code, the signature will always be valid since we hardcoded in the private and public keys
        # Normally, you would want to use the keys generated by the keypair generated, where the PK is password protected
        verification_result = publicKey.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        # the function will return (None) if the signature is valid
        if verification_result == None:
            status = "Signature is valid."
        else:
            status = "Signature verification failed."
        returnSign = signature.hex()
    return render_template("patientvisit.html", status = status ,signature=returnSign)

if __name__=='__main__':
    webbrowser.open("http://127.0.0.1/home") 
    app.run(host='0.0.0.0', port=80)