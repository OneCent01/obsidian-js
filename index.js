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
const SECRET_KEY = "secretkey23456"
const expiresInDefault = 24 * 60 * 60
const defaultTokenOpts = {
	expiresIn: expiresInDefault, 
	secretKey: SECRET_KEY
}
const issueToken = (id, opts=defaultTokenOpts) => jwt.sign(
	{ id }, // paylod
	opts.secretKey, // private key
	{ expiresIn: opts.expiresIn } // sign options
)

var base64 = {
	encode: unencoded => Buffer.from(unencoded || '').toString('base64'),
	decode: encoded => Buffer.from(encoded || '', 'base64').toString('utf8'),
	urlEncode: unencoded => base64.encode(unencoded).replace('\+', '-').replace('\/', '_').replace(/=+$/, ''),
	urlDecode: encoded => base64.decode(`${encoded.replace('-', '+').replace('_', '/')}${new Array(encoded % 4).fill('=').join('')}`)
}

const verifyToken = (token, opts=defaultTokenOpts) => {
	try {
		const { expiresIn, secretKey } = opts
		const decodedPayload = jwt.verify(token, secretKey, { expiresIn })
		const payload = base64.urlEncode(JSON.stringify(decodedPayload))
		const headers = base64.urlEncode(JSON.stringify({
			"alg": "HS256",
			"typ": "JWT"
		}))
		const tokenSig = token.split('.')[2]
		const signiature = crypto.createHmac('SHA256', secretKey)
		.update(`${headers}.${payload}`).digest('base64')
		.replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_")
		return {
			success: signiature === tokenSig, 
			user: decodedPayload
		}
	} catch(e) {
		return {
			success: false
		}
	}
}

const argonGems = {
	secureRandom,
	secureSalt,
	hash,
	verify,
	issueToken,
	verifyToken
}

module.exports = argonGems