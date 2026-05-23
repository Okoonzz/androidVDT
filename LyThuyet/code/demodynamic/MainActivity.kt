package com.example.dynamicloaderdemo

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import com.example.dynamicloaderdemo.ui.theme.DynamicLoaderDemoTheme
import androidx.compose.runtime.remember
import androidx.compose.ui.platform.LocalContext

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            DynamicLoaderDemoTheme {
                Scaffold(modifier = Modifier.fillMaxSize()) { innerPadding ->
                    Greeting(
                        name = "Android",
                        modifier = Modifier.padding(innerPadding)
                    )
                }
            }
        }
    }
}

//đánh dấu một function là Compose UI function
//có thể được gọi trong setContent { ... } hoặc từ composable khác
@Composable
fun Greeting(name: String, modifier: Modifier = Modifier) {
    // lấy context android
    //vì greeting không phải là activity, chỉ là compose nên phải dùng như thế
    val context = LocalContext.current

    //giúp Compose nhớ lại kết quả qua các lần recomposition
    //khi state thay đổi, màn hình có thể re-render. Nếu không dùng remember, có thể chạy lại nhiều lần PluginLoader.loadAndRun(context)
    val result = remember {
        try {
            //vì ở loader khai báo object nên không cần loader = PluginLoader()
            //có thể call thẳng
            PluginLoader.loadAndRun(context)
        } catch (e: Exception) {
            "Load plugin failed: ${e.message}"
        }
    }

    Text(
        text = result,
        modifier = modifier
    )
}

@Preview(showBackground = true)
@Composable
fun GreetingPreview() {
    DynamicLoaderDemoTheme {
        Greeting("Android")
    }
}