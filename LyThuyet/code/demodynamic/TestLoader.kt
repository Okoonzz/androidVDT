package com.example.dynamicloaderdemo

//cho phép code truy cập vào assests, filedsdir,...
import android.content.Context

//  Loader method tham khảo thêm tại https://developer.android.com/reference/dalvik/system/DexClassLoader
import dalvik.system.DexClassLoader

import java.io.File
import java.security.MessageDigest

//crypto
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

object PluginLoader {

    //path enc file at app/src/main/assets/test.enc
    private const val ASSET_NAME = "test.enc"

    // hash file original
    private const val EXPECTED_SHA256 =
        "2e4e63f11488df916d05087ab1133a196439abbdca54367c1c73a5374dca2d47"


    fun loadAndRun(context: Context): String {
        //open file at assets and read
        val encrypted = context.assets.open(ASSET_NAME).use {
            it.readBytes()
        }

        //decrypt
        val plainJar = decryptAesGcm(encrypted)

        // calculate hash and compare
        val actualHash = sha256Hex(plainJar)
        require(actualHash.equals(EXPECTED_SHA256, ignoreCase = true)) {
            "Plugin integrity check failed. Actual SHA-256: $actualHash"
        }

        //create path to contain decrypt
        //path private ex:/data/user/0/com.example.dynamicloaderdemo/files/plugins
        //write decrypt byte into testass-plugin.jar on disk, then set readonly
        val pluginDir = File(context.filesDir, "plugins")
        pluginDir.mkdirs()

        val jarFile = File(pluginDir, "testass-plugin.jar")
        if (jarFile.exists()) {
            jarFile.delete()
        }

        jarFile.outputStream().use {
            it.write(plainJar)
            it.flush()
        }

        jarFile.setReadOnly()


        //DexClassLoader cần một file path thật trên filesystem
        val loader = DexClassLoader(
            jarFile.absolutePath,
            context.codeCacheDir.absolutePath,
            null, //librarySearchPath, dùng nếu plugin cần load native lib, trỏ tới thư mục chứa lib
            context.classLoader
        )

        //tìm class trong decrypt file
        val clazz = loader.loadClass("com.example.plugin.testass")

        //create instance
        // get constructor ko tham số và call constructor đó để tạo object
        // nếu ko có thì java tự tạo
        val instance = clazz.getDeclaredConstructor().newInstance()

        //lấy method message
        val method = clazz.getMethod("message")

        return method.invoke(instance) as String
    }

    private fun decryptAesGcm(input: ByteArray): ByteArray {
        require(input.size > 12) {
            "Invalid encrypted plugin"
        }

        val iv = input.copyOfRange(0, 12)
        val key = input.copyOfRange(12,44)
        val ciphertext = input.copyOfRange(44, input.size)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val keySpec = SecretKeySpec(key, "AES")
        val gcmSpec = GCMParameterSpec(128, iv)

        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec)
        return cipher.doFinal(ciphertext)
    }

    private fun sha256Hex(data: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(data)
        return digest.joinToString("") {
            "%02x".format(it)
        }
    }
}
