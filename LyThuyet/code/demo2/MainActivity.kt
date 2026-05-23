package com.example.testapp

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Text
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

class MainActivity : ComponentActivity() {

    external fun nativeShowStack(label: String): String

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        setContent {
            val output = remember {
                mutableStateOf("Stacktrace / Native Stack Demo\n")
            }

            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(16.dp)
                    .verticalScroll(rememberScrollState())
            ) {
                Button(
                    onClick = {
                        output.value = trustedNativeEntry()
                    }
                ) {
                    Text("Trusted Native Stack")
                }

                Button(
                    onClick = {
                        output.value = stackReportStrong("DIRECT_STACK_REPORT_CALL")
                    }
                ) {
                    Text("Direct Stack Report")
                }

                Button(
                    onClick = {
                        output.value = nativeShowStack("DIRECT_NATIVE_ONLY_CALL")
                    }
                ) {
                    Text("Native Stack Only")
                }

                Text(
                    text = output.value,
                    modifier = Modifier.padding(top = 16.dp)
                )
            }
        }
    }

    /*
     * Luồng hợp lệ:
     *
     * Button
     *   -> trustedNativeEntry()
     *      -> nativeWrapperA()
     *         -> nativeWrapperB()
     *            -> stackReportStrong()
     *               -> nativeShowStack()
     */
    fun trustedNativeEntry(): String {
        return nativeWrapperA()
    }

    fun nativeWrapperA(): String {
        return nativeWrapperB()
    }

    fun nativeWrapperB(): String {
        return stackReportStrong("TRUSTED_NATIVE_FLOW")
    }

    /*
     * Hàm này in Java/Kotlin stack trước,
     * sau đó gọi nativeShowStack() để in native stack.
     */
    fun stackReportStrong(source: String): String {
        val javaStack = Throwable().stackTrace

        val mainClass = "com.example.testapp.MainActivity"

        val expectedOrder = listOf(
            "$mainClass.stackReportStrong",
            "$mainClass.nativeWrapperB",
            "$mainClass.nativeWrapperA",
            "$mainClass.trustedNativeEntry"
        )

        fun StackTraceElement.signature(): String {
            return "$className.$methodName"
        }

        val signatures = javaStack.map { it.signature() }

        val startIndex = signatures.indexOf(expectedOrder[0])

        val exactOrderMatch =
            startIndex >= 0 &&
                    expectedOrder.indices.all { i ->
                        signatures.getOrNull(startIndex + i) == expectedOrder[i]
                    }

        val suspiciousKeywords = listOf(
            "frida",
            "gum",
            "gadget",
            "xposed",
            "lsposed",
            "substrate",
            "riru",
            "zygisk"
        )

        val suspiciousFrame = signatures.any { sig ->
            val lower = sig.lowercase()
            suspiciousKeywords.any { keyword -> lower.contains(keyword) }
        }

        val reflectionOrProxyFrame = signatures.any { sig ->
            sig == "java.lang.reflect.Method.invoke" ||
                    sig.contains("kotlin.reflect", ignoreCase = true) ||
                    sig.contains("proxy", ignoreCase = true)
        }

        val javaStatus = when {
            suspiciousFrame -> "SUSPICIOUS - Java stack contains instrumentation keyword"
            reflectionOrProxyFrame -> "SUSPICIOUS - Java stack contains reflection/proxy frame"
            exactOrderMatch -> "MATCH - exact Java stack order is valid"
            else -> "MISMATCH - exact Java stack order is invalid"
        }

        val javaStackText = javaStack.mapIndexed { index, frame ->
            "#$index ${frame.className}.${frame.methodName}(${frame.fileName}:${frame.lineNumber})"
        }.joinToString("\n")

        val nativeText = nativeShowStack(source)

        return """
            [FULL STACK REPORT]
            source: $source
            
            [JAVA EXACT STACK ORDER CHECK]
            Expected order:
            0. ${expectedOrder[0]}
            1. ${expectedOrder[1]}
            2. ${expectedOrder[2]}
            3. ${expectedOrder[3]}
            
            found start index: $startIndex
            exact order match: $exactOrderMatch
            suspicious Java frame: $suspiciousFrame
            reflection/proxy frame: $reflectionOrProxyFrame
            
            Java status: $javaStatus
            
            Java/Kotlin stack:
            $javaStackText
            
            $nativeText
        """.trimIndent()
    }

    companion object {
        init {
            System.loadLibrary("integritydemo")
        }
    }
}