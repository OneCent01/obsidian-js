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
*/
const hash = async (saltedPass) => await argon2.hash(saltedPass)

/*
	@verify: async function verifying the given salted password is the same as the 
			one used to generate it
		*saltedPass: string, the user's entered password concatenated with a salt
		*hash: string, argon2 hash saved in association with the user
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
		const tokenOpts = {
			...defaultVerifyTokenOpts.tokenOpts, 
			...(typeof opts.tokenOpts === 'object' ? opts.tokenOpts : {})
		}
		const { expiresIn, secretKey } = tokenOpts

		const decodedPayload = jwt.verify(
			token, 
			secretKey, 
			{ expiresIn }
		)
		return {success: true, user: decodedPayload}
	} catch(e) {
		return {success: false, error: e}
	}
}

const validSettings = ['DENY', 'SAMEORIGIN']

const validFrameOptSetting = (opts={}) => {
	let setting = (
		opts.setting 
		&& typeof setting === 'string' 
		&& opts.setting.toUpperCase()
	)
	
	if(setting === 'ALLOW-FROM') {
		const validDomain = (
			opts.domain 
			&& typeof opts.domain === 'string' 
			&& opts.domain.length
		)
		setting = validDomain ? `${setting} ${opts.domain}` : 'SAMEORIGIN'
	} else if(!validSettings.includes(setting)) {
		setting = 'SAMEORIGIN'
	} 

	return setting
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

// check the whether the token was sent in and if it's valid
const verifyReqToken = (token, verify=verifyToken, opts={}) => (
	token 
	&& token.length 
	&& verify(token, opts)
)

const verifyReqTokenWare = (opts={}) => (req, res, next) => {
	const unrestrictedPaths = opts.unrestrictedPaths || []
	const isUnrestricted = unrestrictedPaths.includes(req.path)
	// if the use is attempting to ping one of the unrestricted
	// endpoints, let them through. Otherwise, 
	if(!isUnrestricted) {
		// not unrestricted, now verify the token....
		const headers = req.headers
		const token = headers.authorization
		const verification = verifyReqToken(token, opts.verify, opts.verifyOpts)
		
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

const validXssProtectionSetting = (opts={}) => {
	const settingIsGiven = (opts.setting !== undefined && typeof +opts.setting === 'number')
	let setting = settingIsGiven ? +opts.settings : 1
	if(setting === 1) {
		const modeKey = ['mode', 'report'].includes(opts.mode) ? opts.mode : 'mode'
		const useReport = (
			modeKey === 'report' 
			&& opts.report 
			&& opts.report.length
		)
		return `${setting}${useReport ? `; report=${opts.report}` : '; mode=block'}`
	} else {
		return '0'
	}

}

const xssProtectionWare = (opts={}) => (req, res, next) => {
	res.setHeader('X-XSS-Protection', validXssProtectionSetting(opts))
	next()
}

const contentTypeWare = (opts={}) => (req, res, next) => {
	res.setHeader('X-Content-Type-Options', 'nosniff')
	next()
}


const frameOptionsWare = (opts={}) => (req, res, next) => {
	res.setHeader('X-Frame-Options', validFrameOptSetting(opts))
	next()
}

const obsidianWare = (opts={}) => (req, res, next) => {
	const disableFrameSecurity = typeof opts.disableFrameSecurity === 'boolean' ? opts.disableFrameSecurity : false
	if(!disableFrameSecurity) {
		res.setHeader('X-Frame-Options', validFrameOptSetting(opts.frameOpts))
	}

	const disableXssProtectionSecurity = typeof opts.disableXssProtectionSecurity === 'boolean' ? opts.disableXssProtectionSecurity : false
	if(!disableXssProtectionSecurity) {
		res.setHeader('X-XSS-Protection', validXssProtectionSetting(opts.xssProtectionOpts))
	}

	const disableContentTypeSecurity = typeof opts.disableContentTypeSecurity === 'boolean' ? opts.disableContentTypeSecurity : false
	if(!disableContentTypeSecurity) {
		res.setHeader('X-Content-Type-Options', 'nosniff')
	}
	
	const isUnrestricted = (opts.unrestrictedPaths || []).includes(req.path)
	// if the use is attempting to ping one of the unrestricted
	// endpoints, let them through. Otherwise, 
	if(!isUnrestricted) {

		const headers = req.headers
		const token = headers.authorization
		const verification = verifyReqToken(token, opts.verify, opts.verifyOpts)
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
	verifyHash,
	issueToken,
	verifyToken,
	verifyReqToken,
	validFrameOptSetting,
	validXssProtectionSetting,
	obsidianWare,
	verifyReqTokenWare,
	frameOptionsWare,
	xssProtectionWare,
	contentTypeWare,
	verifyRequest: verifyReqTokenWare,
	setFrameHeader: frameOptionsWare,
	verify: verifyHash
}