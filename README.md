# Obsidian-JS
## *Fortify your Node server with rock hard authentication*

<img style="float:right;" src="https://gamepedia.cursecdn.com/minecraft_gamepedia/2/23/Obsidian.png"/>

A light library of pure functions useful for secure server-side development in Node.JS. Provides a set of easy-to-use tools that allows for rapid development of secure servers. It relies on argon2 for password hashing/verification and jsonwebtoken for token generation/authentication. 


## Installing

In a terminal, navigate to the root of the application to add the library, and run:

`$ npm install --save obsidian-js`

The obsidian module can now be made available in the node files using `require`:

```
const obsidian = require('obsidian-js')

// all available utilities: 
const {
	secureRandom,
	secureSalt,
	hash,
	verifyHash,
	issueToken,
	verifyToken,
	verifyRequest
} = obsidian
```


## Docs


**secureRandom(length, type)**

async function securely generating random sequences using Node's crypto module

	-length: integer, how long the returned sequence should be

	-type: stirng, supports hex strings ('hex') and integers ('int')

	-> returns a promise resolved with the random sequence or rejecting with a `false` boolean and an error


**secureSalt(length, type)**

async function securely generating random a salt of given length and type using Node's crypto module

	-length: integer, how long the returned salt should be

	-type: string, the type of salt desired, currently only supports 'hex' and 'int' types

	-> returns a promise resolved with the random sequence or rejecting with a `false` boolean


**hash(saltedPass)**

async hashing function using the argon2 algorithm

	-saltedPass: string, the user's password concatenated with a salt

	-> returns a promise resolved with a hashed string


	Only call this function when setting a password.

	Saving plaintext passwords is VERY BAD!!


	To avoid saving user passwords, save the salt and returned 
	hash in association with the user. These will be used later 
	for identity verification without exposing the original 
	password.


**verifyHash(saltedPass, hash)**

async function verifying the given salted password is the same as the one used to originally generate the given hash

	-saltedPass: string, the user's entered password concatenated with a salt

	-hash: string, argon2 hash saved in association with the user

	-> returns a promise resolved with a boolean


	When a login request is made, the server needs to ensure 
	the person requesting the resource is who they say they 
	are. Fetch the user's login info from yourdatabase, which 
	should include a hash and salt. 

	DO NOT try and re-hash the salted password and compare it 
	to the previous hash, that won't work. There's a degree of 
	random in the hashing algorithm, meaning the same password 
	won't hash into the same thing twice. 

	argon2's verify takes this into account and can ensure the given password was 
	used to generate the hash using magic. 


**issueToken(data, opts)**

synchronously generates and returns a JSON web token
	-data: ANY, identifying information required for user permissions
				-> the payload can be stringifiable value or data structure


	-opts: object, contains the secret key and signing options

	-> returns a json web token string


	This token should be kept in memory, sent in on every
	seubsequent request on the `Authorization` header.

```
// example call: 
const userToken = issueToken({/*USERDATA*/}, {
	secretKey: 'GlowInTheDarkDemons',
	signOpts: {expiresIn: (24 * 60)}
})

// store locally using localStorage browser API
localStorage.setItem('token', userToken)

// sending in the token:
const fetch = (method, url, payload=undefined) => new Promise((resolve, reject) => {
	const request = new XMLHttpRequest()

	// ...

	const token = localStorage.getItem('token')
	if(token) {
		request.withCredentials = true
		request.setRequestHeader('Authorization', token)
	}
	request.send(payload)
})

```


**verifyToken(token, opts)**

synchronously ensures the token is valid, has not expired, and has not been tampered with

	-token: json web token returned from issueToken

	-opts: object, can contain two sub objects to overwrite defaults. MUST match the parameters used when generating the hash for verification to succeed. 

	-> returns an object with a `success` property indicating the token's validity, and either an `error` string or a `user` prop with the token's decoded payload 


```
// example call: 
verifyToken(<TOKEN>, {
	headerOpts: {alg: 'RS256'},
	tokenOpts: {
		expiresIn: (24 * 60),
		secretKey: 'GlowInTheDarkDemons'
	}
})
```

**verifyRequest**

Middleware function for Express.JS check the token sent in with the request. If it's invalid, expired, or been tampered with, immediately reject the request. Otherwise, the user is valid. Allow the request to continue  falling through the Express functions.
	
	-opts: object, must contain an array of strings at `unrestrictedPaths`. Optional props:
		*verify: function, must return an object with a success property. uses `obsidian.verifyToken` by default
		*verifyOpts: an object to be passed to the verfy function as the second argument after the token

	-> returns a function that accepts three arguments (req, res, next) which ensures the token attached to the request's Authorization header is valid


```
// example call:

const unrestrictedPaths = ['/auth-user', '/add-user']
const verificationMiddleware = verifyRequest({ unrestrictedPaths })

// every request will be passed through this endpoint,
// to check the senders credentials (token) and possibly  
// terminate the endpoint fallthrough
app.use(verificationMiddleware)
```