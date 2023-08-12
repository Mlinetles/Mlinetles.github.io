(function (root) {
    async function AESDecrypt(url, key, iv, base64 = true, asBlob = false) {
        key = aesjs.utils.utf8.toBytes(key)

        iv = aesjs.utils.utf8.toBytes(iv)

        const file = await fetch(url)

        const content = base64 ? Base64.toUint8Array(asBlob ? new Uint8Array(await file.arrayBuffer()) : await file.text())
            : (asBlob ? new Uint8Array(await file.arrayBuffer()) : await file.text())

        return asBlob ? new aesjs.ModeOfOperation.ofb(key, iv).decrypt(content)
            : aesjs.utils.utf8.fromBytes(new aesjs.ModeOfOperation.ofb(key, iv).decrypt(content))
    }

    async function AESEncrypt(content, key, iv, base64 = true, asString = true) {
        key = aesjs.utils.utf8.toBytes(key)

        iv = aesjs.utils.utf8.toBytes(iv)
        
        const bytes = asString ? aesjs.utils.utf8.toBytes(content)
            : new Uint8Array(await content.arrayBuffer())

        return base64 ? Base64.fromUint8Array(new aesjs.ModeOfOperation.ofb(key, iv).encrypt(bytes))
            : new aesjs.ModeOfOperation.ofb(key, iv).encrypt(bytes)
    }

    async function GetMtml(url, key, iv, base64 = true, asBlob = false) {
        if (key.length !== 32) {
            alert(`密钥的字节数必须为32！当前为${typeof key != 'undefined' ? key.length : 0}`)

            return ''
        }

        if (iv.length !== 16) {
            alert(`向量的字节数必须为16！当前为${typeof iv != 'undefined' ? iv.length : 0}`)

            return ''
        }

        if (typeof url !== 'string') {
            alert('URL必须为字符串！')

            return ''
        }

        else {
            return await AESDecrypt(url, key, iv, base64, asBlob)
        }
    }

    function GetMtmlCall(url, key, iv, callback, setting, base64 = true, asBlob = false) {
        const xhr = new XMLHttpRequest()

        if (key.length !== 32) {
            alert(`密钥的字节数必须为32！当前为${typeof key != 'undefined' ? key.length : 0}`)

            return ''
        }

        if (iv.length !== 16) {
            alert(`向量的字节数必须为16！当前为${typeof iv != 'undefined' ? iv.length : 0}`)

            return ''
        }

        if (typeof url !== 'string') {
            alert('URL必须为字符串！')

            return ''
        }

        else {
            key = aesjs.utils.utf8.toBytes(key)

            iv = aesjs.utils.utf8.toBytes(iv)

            xhr.open('GET', url)

            if (asBlob)
                xhr.responseType = 'arraybuffer'

            setting(xhr)

            xhr.onload = e => {
                const content = base64 ? Base64.toUint8Array(xhr.response) : xhr.response

                callback(asBlob ? new aesjs.ModeOfOperation.ofb(key, iv).decrypt(new Uint8Array(content))
                    : aesjs.utils.utf8.fromBytes(new aesjs.ModeOfOperation.ofb(key, iv).decrypt(content)))
            }

            xhr.send()
        }
    }

    async function Encrypt(content, key, iv, asBlob = false) {
        if (key.length !== 32) {
            alert(`密钥的字节数必须为32！当前为${typeof key != 'undefined' ? key.length : 0}`)

            return ''
        }

        if (iv.length !== 16) {
            alert(`向量的字节数必须为16！当前为${typeof iv != 'undefined' ? iv.length : 0}`)

            return ''
        }

        if (typeof content !== (asBlob ? 'object' : 'string')) {
            alert(asBlob ? '内容必须为对象！' : '内容必须为字符串！')

            return ''
        }

        else {
            if (asBlob)
                return await AESEncrypt(content, key, iv, false, false)

            else
                return await AESEncrypt(content, key, iv)
        }
    }

    async function EncryptFile(pdf = false) {
        const input = document.createElement('input')

        input.type = 'file'

        input.accept = pdf ? '.pdf' : '.html'

        input.onchange = async e => {
            if (input.files.length !== 0) {
                for (let i = 0, len = input.files.length; i < len; i++) {
                    const text = new Blob(pdf ? [await root.Encrypt(
                        input.files[i],

                        document.querySelector('#key').value,
                
                        document.querySelector('#iv').value, true)]

                        : [await root.Encrypt(
                        await input.files[i].text(),

                        document.querySelector('#key').value,
                
                        document.querySelector('#iv').value)], {
                            type: 'application/force-download;charset=UTF-8'
                        })

                    if (text.size !== 0) {
                        const download = document.createElement('a')
                        
                        const url = window.URL.createObjectURL(text)

                        download.href = url

                        download.download = input.files[i].name.replace(pdf ? '.pdf' : '.html', pdf ? '.mdf' : '.mtml')

                        download.click()

                        window.URL.revokeObjectURL(url)
                    }
                }
            }
        }

        input.click()
    }

    if (typeof aesjs === 'undefined')
        throw new Error('aes-js未能正常加载！')
    
    else if (typeof Base64 === 'undefined')
        throw new Error('js-base64未能正常加载！')
    
    else {
        root.GetMtml = GetMtml

        root.GetMtmlCall = GetMtmlCall

        root.Encrypt = Encrypt

        root.EncryptFile = EncryptFile
    }
})(this)