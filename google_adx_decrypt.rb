google_adx_encryption_key = "\xb0\x8c\x70\xcf\xbc\xb0\xeb\x6c\xab\x7e\x82\xc6\xb7\x5d\xa5\x20\x72\xae\x62\xb2\xbf\x4b\x99\x0b\xb8\x0a\x48\xd8\x14\x1e\xec\x07"
google_adx_integrity_key = "\xbf\x77\xec\x55\xc3\x01\x30\xc1\xd8\xcd\x18\x62\xed\x2a\x4c\xd2\xc7\x6a\xc3\x3b\xc0\xc4\xce\x8a\x3d\x3b\xbd\x3a\xd5\x68\x77\x92"
ed = 'SjpvRwAB4kB7jEpgW5IA8p73ew9ic6VZpFsPnA'

require 'base64'
require 'facets/string/xor'
require 'openssl'

def websafe_pad(str)
	pad = "";
    if str.length%4== 2
      pad = "==";
    elsif str.length%4 == 3
      pad = "=";
    end
    str = str+pad
    str.tr('-_','+/')    
end

def decrypt(encrypted_data,google_adx_encryption_key,google_adx_integrity_key)
	enc_key = google_adx_encryption_key
	ciphertext = Base64.urlsafe_decode64(encrypted_data)
	plaintext_length = ciphertext.length-16-4
	iv = ciphertext[0..15]
	ciphertext_end = 16+plaintext_length
	add_iv_counter_byte = true
	ciphertext_begin=16
	plaintext_begin=0
	plaintext = Array.new
	while ciphertext_begin<ciphertext_end do
		digest = OpenSSL::Digest.new('sha1')
		pad = OpenSSL::HMAC.digest(digest, enc_key, iv)	
		i = 0	
		while (i<20 and ciphertext_begin != ciphertext_end) do				 
			plaintext[plaintext_begin] = ciphertext[ciphertext_begin] ^ pad[i]
			plaintext_begin+=1
			ciphertext_begin+=1
			i+=1				
		end

	 	unless add_iv_counter_byte
	 		index = iv.length - 1;
	 		iv[index] = (iv[index].ord+1).chr
	 		add_iv_counter_byte = iv[index] == 0;
	 	end
	    if add_iv_counter_byte      
	    	add_iv_counter_byte = false
	    	iv += "\x0"
	    end         
	end
	#Integrity Checks
	sig = ciphertext[24..27]
	int_key = google_adx_integrity_key
	digest = OpenSSL::Digest.new('sha1')
	conf_sig = OpenSSL::HMAC.digest(digest, int_key, plaintext.join('')+ciphertext[0..15])
	if conf_sig[0..3]==sig
		j =plaintext.join("")
		p j.unpack("H*").first.to_i(16).to_s(10)
	else
		p "Signature mismatch"
	end
end

ed = websafe_pad(ed)
decrypt(ed,google_adx_encryption_key,google_adx_integrity_key)