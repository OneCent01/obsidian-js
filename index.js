const crypto = require('crypto')

/*
	@secureRandom: securely generate random sequences using Node's crypto module
		*length: integer, how long the returned sequence should be
		*type: stirng, supports hex strings ('hex') and integers ('int')
*/
const secureRandom = (length=0, type='hex') => new Promise((resolve, reject) => {
	crypto.randomBytes(Math.ceil(length/2), (err, buff) => {
		if(err !== null) {
			reject(err)
		} else {
			const randHex = buff.toString('hex')

			type = type.toLowerCase()
			if(type === 'hex') {
				resolve(randHex.slice(0, length))
			} else if(type === 'int') {
				const randInt = parseInt(randHex, 16)
				const sizedRandInt = randInt.toString().slice(0, length)
				resolve(+sizedRandInt)
			} else {
				reject(false, 'UNKNOWN `type` REQUESTED IN `secureRandom` FUCNTION')
			}
		}
	})
})

const argon2 = require('argon2')

/*
	@hash: async hashing function using the argon2 algorithm
		*saltedPass: string, the user's password concatenated with a salt

	Only call this function when setting a password.

	Saving plaintext passwords is VERY BAD!!

	To avoid saving user passwords, save the salt and returned hash in association with
	the user. These will be used later for identity verification without exposing
	the original password. 
*/
const hash = async (saltedPass) => await argon2.hash(saltedPass)

/*
	@verify: async function verifying the given salted password is the same as the 
			one used to generate it
		*saltedPass: string, the user's entered password concatenated with a salt
		*hash: string, argon2 hash saved in association with the user

	When a login request is made, the server needs to ensure the person requesting
	the resource is who they say they are. Fetch the user's login info from your
	database, which should include a hash and salt. 

	DO NOT try and re-hash the salted password and compare it to the previous hash,
	that won't work. There's a degree of random in the hashing algorithm, meaning 
	the same password won't hash into the same thing twice. 

	argon2's verify takes this into account and can ensure the given password was 
	used to generate the hash using magic. 
*/
const verifyHash = async (saltedPass, hash) => await argon2.verify(hash, saltedPass)
const defaultSaltOpts = {
	length: 16,
	type: 'hex'
}

/*
	@secureSalt: async function securely generating random a salt of given length 
			and type using Node's crypto module
		*length: integer, how long the returned salt should be
		*type: string, the type of salt desired, currently only supports 'hex' and 'int' types
*/
const secureSalt = async (opts) => await secureRandom(
	opts.length && opts.length > 0 ? opts.length : defaultSaltOpts.length, 
	opts.type || defaultSaltOpts.type
)

const jwt  =  require('jsonwebtoken')
const SECRET_KEY = "AlexJonesDidNothingWrong" // shhh don't tell
const expiresInDefault = 24 * 60 * 60
const defaultTokenOpts = {
	signOpts: {
		expiresIn: expiresInDefault, 
		algorithm: 'HS256' // use HMAC SHA-256 encryption algorithm
	},
	secretKey: SECRET_KEY
}

/*
	@issueToken: synchronously generates and returns a JSON web token
		*data: ANY, identifying information required for user permissions
				-> the payload can be stringifiable value or data structure
		*opts: object, contains the secret key and signing options
				-> example: {
					secretKey: 'GlowInTheDarkDemons',
					signOpts: {expiresIn: (24 * 60)}
				}
*/
const issueToken = (data, opts={}) => {
	const signOpts = { // sign options
		...defaultTokenOpts.signOpts, 
		...(typeof opts.signOpts === 'object' ? opts.signOpts : {}) 
	} 
	const token = jwt.sign(
		{ data }, // paylod
		opts.secretKey || defaultTokenOpts.secretKey, // private key
		signOpts
	)

	return token
}

// Node JS base 64 conversion utilities
var base64 = {
	encode: unencoded => Buffer.from(unencoded || '').toString('base64'),
	decode: encoded => Buffer.from(encoded || '', 'base64').toString('utf8'),
	urlEncode: unencoded => base64.encode(unencoded).replace('\+', '-').replace('\/', '_').replace(/=+$/, ''),
	urlDecode: encoded => base64.decode(`${encoded.replace('-', '+').replace('_', '/')}${new Array(encoded % 4).fill('=').join('')}`)
}

const defaultVerifyTokenOpts = {
	headerOpts: {
		"alg": "HS256",
		"typ": "JWT"
	},
	tokenOpts: {
		expiresIn: expiresInDefault,
		secretKey: SECRET_KEY
	}
}

/*
	@verifyToken: ensures the token is valid, has not expired, and has not been tampered with
		*token: json web token, should have three character sequences sepearated by periods
		*opts: object, can contain two sub objects to overwrite defaults. MUST match the parameters
			used when generating the hash for verification to succeed. 
				-> example: {
					headerOpts: {alg: 'RS256'},
					tokenOpts: {
						expiresIn: (24 * 60),
						secretKey: 'GlowInTheDarkDemons'
					}
				}
*/
const verifyToken = (token, opts={}) => {
	try {
		const { 
			expiresIn, 
			secretKey 
		} = {
			...defaultVerifyTokenOpts.tokenOpts, 
			...(typeof opts.tokenOpts === 'object' ? opts.tokenOpts : {})
		}
		const decodedPayload = jwt.verify(
			token, 
			secretKey, 
			{ expiresIn }
		)
		const payload = base64.urlEncode(JSON.stringify(decodedPayload))
		const header = base64.urlEncode(JSON.stringify({
			...defaultVerifyTokenOpts.headerOpts, 
			...(typeof opts.headerOpts === 'object' ? opts.headerOpts : {})
		}))
		const tokenSig = token.split('.')[2]
		const signiature = (
			crypto
			.createHmac('SHA256', secretKey)
			.update(`${header}.${payload}`)
			.digest('base64')
			.replace(/=/g, "")
			.replace(/\+/g, "-")
			.replace(/\//g, "_")
		)
		return (
			signiature === tokenSig
			? {success: true, user: decodedPayload}
			: {success: false, error: 'INVALID_TOKEN'}
		)
	} catch(e) {
		return {success: false, error: JSON.stringify(e)}
	}
}

const defaultReqVerificationOpts = {
	unrestrictedPaths: [],
	verify: verifyToken
}

/*
	@verifyRequest: middleware function for Express.JS check the token sent in with
			the request. If it's invalid, expired, or been tampered with, immediately
			reject the request. Otherwise, the user is valid. Allow the request to continue 
			falling through the Express functions.
		*opts: object, should contain an array at unrestrictedPaths and can be passed a 
			verification function to pass the token through. (MUST return an object with a 
			success property)
*/
const verifyRequest = (opts={}) => (req, res, next) => {
	const path = req.path 
	const unrestrictedPaths = opts.unrestrictedPaths || defaultReqVerificationOpts.unrestrictedPaths
	const verify = opts.verify || defaultReqVerificationOpts.verify
	const verifyOpts = opts.verifyOpts || {}
	// if the use is attempting to ping one of the unrestricted
	// endpoints, let them through. Otherwise, 
	if(!unrestrictedPaths.includes(path)) {
		const headers = req.headers
		const token = headers.authorization
		// check the whether the token was sent in and if it's valid
		const verification = (token && token.length && verify(token, verifyOpts))
		if(verification) {
			if(verification.success) {
				// attach the user data to the request object passed 
				// to the next endpoint
				req.user = verification.user
				next()
			} else {
				res.send(JSON.stringify(verification))
			}
		} else {
			res.send(JSON.stringify({
				success: false,
				error: 'TOKENLESS'
			}))
		}
	} else {
		next()
	}

}

module.exports = {
	secureRandom,
	secureSalt,
	hash,
	issueToken,
	verifyToken,
	verifyRequest,
	verifyHash,
	verify: verifyHash,
}