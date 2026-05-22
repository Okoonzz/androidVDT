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

    external fun initBaseline(): String
    external fun checkPrologue(): String
    external fun callSensitiveCheck(x: Int): Int

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        setContent {
            val output = remember {
                mutableStateOf("Native Prologue Integrity Demo\n")
            }

            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(16.dp)
                    .verticalScroll(rememberScrollState())
            ) {
                Button(
                    onClick = {
                        output.value = initBaseline()
                    }
                ) {
                    Text("Init Baseline Bytes")
                }

                Button(
                    onClick = {
                        output.value = checkPrologue()
                    }
                ) {
                    Text("Check Current Bytes")
                }

                Button(
                    onClick = {
                        val ret = callSensitiveCheck(7)
                        output.value = "sensitive_check(7) returned: $ret\n\n" + checkPrologue()
                    }
                ) {
                    Text("Call sensitive_check()")
                }

                Text(
                    text = output.value,
                    modifier = Modifier.padding(top = 16.dp)
                )
            }
        }
    }

    companion object {
        init {
            System.loadLibrary("integritydemo")
        }
    }
}