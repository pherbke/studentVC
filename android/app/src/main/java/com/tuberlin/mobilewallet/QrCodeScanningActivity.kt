package com.tuberlin.mobilewallet

import android.content.Context
import android.util.Log
import android.widget.Toast
import androidx.annotation.OptIn
import androidx.camera.core.CameraSelector
import androidx.camera.core.ExperimentalGetImage
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.google.mlkit.vision.barcode.BarcodeScannerOptions
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.common.InputImage
import com.tuberlin.mobilewallet.qrHandler.qrCodeHandler
import com.tuberlin.mobilewallet.utils.Utilities

@Composable
fun CameraPreview(
    onNavigateBack: () -> Unit, dialogLiveData: MutableLiveData<DialogInfo>,
    cs: CredentialStore? = null
) {

    val localContext = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    val cameraProviderFuture = remember {
        ProcessCameraProvider.getInstance(localContext)
    }

    AndroidView(
        modifier = Modifier.fillMaxSize(),
        factory = { context ->
            val previewView = PreviewView(context)
            val preview = Preview.Builder().build()
            val selector = CameraSelector.Builder()
                .requireLensFacing(CameraSelector.LENS_FACING_BACK)
                .build()

            preview.surfaceProvider = previewView.surfaceProvider

            val imageAnalysis = ImageAnalysis.Builder().build()
            imageAnalysis.setAnalyzer(
                ContextCompat.getMainExecutor(context),
                BarcodeAnalyzer(context, onNavigateBack, dialogLiveData, cs)
            )

            runCatching {
                cameraProviderFuture.get().bindToLifecycle(
                    lifecycleOwner,
                    selector,
                    preview,
                    imageAnalysis
                )
            }.onFailure {
                Log.e("CAMERA", "Camera bind error ${it.localizedMessage}", it)
            }
            previewView
        },
        onRelease = {
            // Release the camera controller when the composable is removed from the screen
            cameraProviderFuture.get().unbind()
        }


    )
}



class BarcodeAnalyzer(
    private val context: Context,
    private val onNavigateBack: () -> Unit,
    private val dialogLiveData: MutableLiveData<DialogInfo>,
    private val cs: CredentialStore?,
    ) : ImageAnalysis.Analyzer {

    private val options = BarcodeScannerOptions.Builder()
        .setBarcodeFormats(Barcode.FORMAT_ALL_FORMATS)
        .build()

    private val scanner = BarcodeScanning.getClient(options)

    private var isProcessingCode = false


    @OptIn(ExperimentalGetImage::class)
    override fun analyze(imageProxy: ImageProxy) {
        if (!isProcessingCode) {
            val mediaImage = imageProxy.image
            mediaImage?.let {
                isProcessingCode = true
                scanner.process(
                    InputImage.fromMediaImage(
                        it,
                        imageProxy.imageInfo.rotationDegrees
                    )
                )
                    .addOnSuccessListener { barcodes ->
                        if (barcodes.isNotEmpty()) {
                            Utilities().vibrateIfAllowed(context,  100)
                            val barcode = barcodes[0]
                            if(barcode.rawValue !== null){
                                val result = qrCodeHandler(barcode.rawValue!!, context, dialogLiveData, cs)
                                Toast.makeText(context, result, Toast.LENGTH_LONG).show()
                                onNavigateBack()
                            } else {
                                isProcessingCode = false
                            }
                        } else {
                            isProcessingCode = false
                        }
                    }
                    .addOnFailureListener { e->
                        e.printStackTrace()
                    }
                    .addOnCompleteListener {
                        imageProxy.image?.close()
                        imageProxy.close()
                    }
            }
        }
    }
}
