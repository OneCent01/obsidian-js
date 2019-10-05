const crypto = require('crypto')
const secureRandom = (length, type) => new Promise((resolve, reject) => {
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
				reject('UNKNOWN `type` REQUESTED IN `secureRandom` FUCNTION')
			}
		}
	})
})

const argon2 = require('argon2')
const hash = async (saltedPass) => await argon2.hash(saltedPass)
const verify = async (saltedPass, hash) => await argon2.verify(hash, saltedPass)
const defaultSaltOpts = {
	length: 16,
	type: 'hex'
}
const secureSalt = async (opts=defaultSaltOpts) => await secureRandom(opts.length, opts.type)

const jwt  =  require('jsonwebtoken')
const SECRET_KEY = "AlexJonesDidNothingWrong" // shhh don't tell
const expiresInDefault = 24 * 60 * 60
const defaultTokenOpts = {
	signOpts: {
		expiresIn: expiresInDefault, 
		algorithm: 'HS256' // use HMAC SHA-256 encryption algorithm
	}
	secretKey: SECRET_KEY
}
const issueToken = (id, opts={}) => jwt.sign(
	{ id }, // paylod
	opts.secretKey || defaultTokenOpts.secretKey, // private key
	{ // sign options
		...defaultTokenOpts, 
		...((opts.signOpts && typeof opts.signOpts === 'object') ? opts.signOpts : {}) 
	} 
)

// Node JS base 64 conversion utilities
var base64 = {
	encode: unencoded => Buffer.from(unencoded || '').toString('base64'),
	decode: encoded => Buffer.from(encoded || '', 'base64').toString('utf8'),
	urlEncode: unencoded => base64.encode(unencoded).replace('\+', '-').replace('\/', '_').replace(/=+$/, ''),
	urlDecode: encoded => base64.decode(`${encoded.replace('-', '+').replace('_', '/')}${new Array(encoded % 4).fill('=').join('')}`)
}

const defaultVerifyTokenOpts = {
	headers: {
		"alg": "HS256",
		"typ": "JWT"
	},
	expiresIn: expiresInDefault,
	secretKey: SECRET_KEY
}
const verifyToken = (token, opts={}) => {
	try {
		const { expiresIn, secretKey } = opts
		const decodedPayload = jwt.verify(
			token, 
			secretKey || defaultVerifyTokenOpts.secretKey, 
			{ expiresIn: expiresIn || defaultVerifyTokenOpts.expiresIn  }
		)
		const payload = base64.urlEncode(JSON.stringify(decodedPayload))
		const headers = base64.urlEncode(JSON.stringify({
			...defaultVerifyTokenOpts.headers, 
			...(opts.headers && typeof opts.headers === 'object' ? opts.headers : {})
		}))
		const tokenSig = token.split('.')[2]
		const signiature = (
			crypto
			.createHmac('SHA256', secretKey)
			.update(`${headers}.${payload}`)
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
		return {success: false, error: e}
	}
}

const defaultReqVerificationOpts = {
	unrestrictedPaths: [],
	verify: verifyToken
}
const verifyRequest = (defaultReqVerificationOpts) => (req, res, next) => {
	const path = req.path 
	const {unrestrictedPaths, verify} = defaultReqVerificationOpts
	// if the use is attempting to ping one of the unrestricted
	// endpoints, let them through. Otherwise, 
	if(!unrestrictedPaths.includes(path)) {
		const headers = req.headers
		const token = headers.authorization
		// check the whether the token was sent in and if it's valid
		const verification = (token && token.length && verify(token))
		if(verification) {
			if(verification.success) {
				// attach the user data to the request object passed 
				// to the next endpoint
				req.user = verification.user.id
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

const obsidian = {
	secureRandom,
	secureSalt,
	hash,
	verify,
	issueToken,
	verifyToken,
	verifyRequest
}

module.exports = obsidian