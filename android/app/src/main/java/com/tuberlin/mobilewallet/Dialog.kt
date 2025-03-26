package com.tuberlin.mobilewallet

import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.lifecycle.MutableLiveData

data class DialogInfo(
    var title: String,
    var message: String,
    val icon: ImageVector
)

@Composable
fun Dialog(dialog: MutableLiveData<DialogInfo>) {
    AlertDialog(
        onDismissRequest = {
            dialog.value = null
        },
        icon = {
            dialog.value?.icon?.let { Icon(it, contentDescription = "Icon") }
        },
        title = { dialog.value?.let { Text(text = it.title) } },
        text = { dialog.value?.let { Text(text = it.message) } },
        confirmButton = {
            Button(
                onClick = {
                    dialog.value = null
                }
            ) {
                Text(
                    text = "Confirm",
                    color = Color.White
                )
            }
        }
    )
}