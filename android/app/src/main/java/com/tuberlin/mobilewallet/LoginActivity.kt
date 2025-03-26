package com.tuberlin.mobilewallet

import android.content.Intent
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.tooling.preview.Preview

import android.app.Activity
import android.content.Context
import android.content.SharedPreferences
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.TextField
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.focus.FocusDirection
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.preference.PreferenceManager
import com.tuberlin.mobilewallet.ui.theme.MobileWalletTheme

class LoginActivity : ComponentActivity() {

    private lateinit var sharedPreferences: SharedPreferences

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        sharedPreferences = PreferenceManager.getDefaultSharedPreferences(this)

        val userCode = sharedPreferences.getString("userCode", "")

        setContent {
            MobileWalletTheme {
                if (userCode == "" || userCode == null) {
                    SetCodeForm(sharedPreferences)
                } else {
                    //SetCodeForm(sharedPreferences)
                    LoginForm(userCode)
                }
            }
        }


    }


}


@Composable
fun SetCodeForm(sharedPreferences: SharedPreferences) {
    Surface {
        var loginCode by remember { mutableStateOf("") }
        val context = LocalContext.current

        Column(
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally,
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 30.dp)
        ) {
            NumericKeyboard(
                value = loginCode,
                onValueChange = { loginCode = it },
                label = "Create Code"
            )
            Spacer(modifier = Modifier.height(10.dp))
            Button(
                onClick = {
                    with(sharedPreferences.edit()) {
                        putString("userCode", loginCode)
                        apply()
                    }
                    context.startActivity(Intent(context, MainActivity::class.java))
                    (context as Activity).finish()
                },
                enabled = loginCode.isNotEmpty(),
                shape = RoundedCornerShape(5.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Create Code")
            }
        }
    }
}


@Composable
fun LoginForm(userCode: String) {
    Surface {
        var loginCode by remember { mutableStateOf("") }
        val context = LocalContext.current

        Column(
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally,
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 30.dp)
        ) {
            NumericKeyboard(
                value = loginCode,
                onValueChange = { loginCode = it },
                label = "Enter your Code"
            )
            Spacer(modifier = Modifier.height(10.dp))
            Button(
                onClick = {
                    if (!checkCredentials(Credentials(loginCode), userCode, context)) loginCode = ""
                },
                enabled = loginCode.isNotEmpty(),
                shape = RoundedCornerShape(5.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Login")
            }
        }
    }
}

fun checkCredentials(creds: Credentials, userCode: String, context: Context): Boolean {
    //check the saved userCode with the login
    if (creds.isNotEmpty() && creds.login == userCode) {
        context.startActivity(Intent(context, MainActivity::class.java))
        (context as Activity).finish()
        return true
    } else {
        Toast.makeText(context, "Wrong Credentials", Toast.LENGTH_SHORT).show()
        return false
    }
}

data class Credentials(
    var login: String = ""
) {
    fun isNotEmpty(): Boolean {
        return login.isNotEmpty()
    }
}


@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun NumericKeyboard(
    value: String,
    onValueChange: (String) -> Unit,
    label: String = "Login",
) {
    val maxLength = 6
    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodyMedium,
            modifier = Modifier.padding(bottom = 16.dp)
        )
        Text(
            text = value,
            style = MaterialTheme.typography.headlineMedium,
            modifier = Modifier.padding(bottom = 16.dp)
        )
        Column(
            modifier = Modifier.fillMaxWidth(),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {

            val numbers = listOf(
                listOf("1", "2", "3"),
                listOf("4", "5", "6"),
                listOf("7", "8", "9"),
                listOf("C", "0", "⌫")
            )
            for (row in numbers) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceEvenly
                ) {
                    for (num in row) {
                        Button(
                            onClick = {
                                when (num) {
                                    "C" -> onValueChange("")
                                    "⌫" -> if (value.isNotEmpty()) onValueChange(value.dropLast(1))
                                    else -> if (value.length < maxLength) onValueChange(value + num)
                                }
                            },
                            modifier = Modifier
                                .size(80.dp)
                                .padding(2.dp),
                            shape = RoundedCornerShape(4.dp),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = Color.LightGray,
                                contentColor = Color.Black
                            ),
                            contentPadding = PaddingValues(0.dp)
                        ) {
                            Box(
                                modifier = Modifier.fillMaxSize(),
                                contentAlignment = Alignment.Center
                            ) {
                                Text(
                                    text = num,
                                    style = MaterialTheme.typography.headlineMedium.copy(fontSize = 28.sp),
                                    textAlign = TextAlign.Center
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}


@Preview(showBackground = true, device = "id:Nexus One", showSystemUi = true)
@Composable
fun LoginFormPreview() {
    LoginForm("")
}

