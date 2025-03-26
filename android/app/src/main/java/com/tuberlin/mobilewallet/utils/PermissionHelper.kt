package com.tuberlin.mobilewallet.utils

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import com.tuberlin.mobilewallet.R

 

class PermissionHelper {

    fun isCameraPermissionGranted(context: Context): Boolean = ContextCompat.checkSelfPermission(
        context,
        Manifest.permission.CAMERA
    ) == PackageManager.PERMISSION_GRANTED

    /**
     * Checks if the camera permission is already granted,
     * and if not, it launches a permission request dialog using the [ActivityResultContracts.RequestPermission] API.
     * It also handles the result of the permission request and shows a [noPermissionDialog] if the permission is denied.
     *
     * @param context Context object of the registering fragment.
     * @param fragment The fragment object that is registering for the permission request result.
     *
     * @see [Manifest.permission.CAMERA]
     */
    fun requestCameraPermission(context : ComponentActivity) {


        if (!isCameraPermissionGranted(context)) {

            ActivityCompat.requestPermissions(
                context,
                arrayOf(Manifest.permission.CAMERA),
                200);

        }
    }

}