package com.tuberlin.mobilewallet.utils

import android.app.Activity
import android.content.Context
import android.content.res.Configuration
import android.graphics.Bitmap
import android.os.Build
import android.os.VibrationEffect
import android.os.Vibrator
import android.os.VibratorManager
import androidx.annotation.AttrRes
import androidx.annotation.ColorInt
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import com.google.zxing.BarcodeFormat
import com.google.zxing.WriterException
import com.google.zxing.common.BitMatrix
import com.google.zxing.qrcode.QRCodeWriter
class Utilities {

    companion object {
        @ColorInt
        fun Context.getColorFromAttr(
            @AttrRes attrColor: Int
        ): Int {
            val typedArray = theme.obtainStyledAttributes(intArrayOf(attrColor))
            val textColor = typedArray.getColor(0, 0)
            typedArray.recycle()
            return textColor
        }

        fun AlertDialog.makeButtonTextTeal(context: Context) {
            this.getButton(AlertDialog.BUTTON_POSITIVE)
                .setTextColor(
                    context.getColorFromAttr(
                        com.google.android.material.R.attr.colorSecondaryVariant
                    )
                )
            this.getButton(AlertDialog.BUTTON_NEGATIVE)
                .setTextColor(
                    context.getColorFromAttr(
                        com.google.android.material.R.attr.colorSecondaryVariant
                    )
                )
        }

        fun isSystemThemeLight(activity: Activity): Boolean =
            activity.resources.configuration.uiMode and
                    Configuration.UI_MODE_NIGHT_MASK == Configuration.UI_MODE_NIGHT_NO
    }

    fun vibrateIfAllowed(context: Context, timeInMillis: Long) {
        val vibrator = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            val vibratorManager =
                context.getSystemService(Context.VIBRATOR_MANAGER_SERVICE) as VibratorManager
            vibratorManager.defaultVibrator
        } else {
            @Suppress("DEPRECATION")
            context.getSystemService(AppCompatActivity.VIBRATOR_SERVICE) as Vibrator
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            vibrator.vibrate(VibrationEffect.createOneShot(timeInMillis, 125))
        } else {
            @Suppress("DEPRECATION")
            vibrator.vibrate(timeInMillis)
        }
    }




    fun generateQRCode(content: String, width: Int = 300, height: Int = 300): Bitmap {
        val qrCodeWriter = QRCodeWriter()
        return try {
            val bitMatrix: BitMatrix = qrCodeWriter.encode(content, BarcodeFormat.QR_CODE, width, height)
            val bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.RGB_565)
            for (x in 0 until width) {
                for (y in 0 until height) {
                    bitmap.setPixel(x, y, if (bitMatrix[x, y]) android.graphics.Color.BLACK else android.graphics.Color.WHITE)
                }
            }
            bitmap
        } catch (e: WriterException) {
            e.printStackTrace()
            // Return a blank bitmap in case of error
            Bitmap.createBitmap(width, height, Bitmap.Config.RGB_565).apply {
                eraseColor(android.graphics.Color.WHITE)
            }
        }
    }

    fun getBarcodeString(credSub: WalletCredential.VerifiedCredential.CredentialSubject): String {
        val aux = credSub.studentIdPrefix
        val aux2 = credSub.studentId
        return aux + aux2
    }






}