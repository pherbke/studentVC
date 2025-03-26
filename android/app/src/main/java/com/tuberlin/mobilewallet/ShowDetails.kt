package com.tuberlin.mobilewallet

import android.annotation.SuppressLint
import android.graphics.BitmapFactory
import android.util.Base64
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.tuberlin.mobilewallet.ui.theme.MobileWalletTheme
import com.simonsickle.compose.barcodes.Barcode
import com.simonsickle.compose.barcodes.BarcodeType
import com.tuberlin.mobilewallet.utils.Utilities
import java.security.KeyPairGenerator

@SuppressLint("UnusedMaterial3ScaffoldPaddingParameter")
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ShowDetailVC(
    cs: CredentialStore,
    onNavigateBack: () -> Unit,
    onNavigateToQrCodeScanner: (String) -> Unit,
) {
    val credSub = cs.credential.vc.credentialSubject
    val imageBytes = Base64.decode(credSub.image, Base64.DEFAULT)
    val decodedImage = BitmapFactory.decodeByteArray(imageBytes, 0, imageBytes.size).asImageBitmap()

    //Decode the Icon
    val iconBytes = Base64.decode(credSub.theme.icon, Base64.DEFAULT)
    val decodedIcon = BitmapFactory.decodeByteArray(iconBytes, 0, iconBytes.size).asImageBitmap()

    val barcode = Utilities().getBarcodeString(credSub)

    Scaffold(
        modifier = Modifier.fillMaxSize(),
        topBar = {
            TopAppBar(
                title = { Text(text = "Detail") },
                navigationIcon = {
                    IconButton(onClick = { onNavigateBack() }) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = "Back"
                        )
                    }
                }


            )
        }
    ) {innerPadding ->
        Column(
            Modifier
                .padding(innerPadding)
                .fillMaxWidth(),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Column(
                Modifier
                    .fillMaxWidth()
                    .padding(start = 10.dp, top = 5.dp, end = 10.dp, bottom = 5.dp)
                    .clip(RoundedCornerShape(10.dp))
                    .shadow(2.dp),
            ) {
                // Top Box
                Box(
                    Modifier
                        .fillMaxWidth()
                        .background(Color(android.graphics.Color.parseColor("#" + credSub.theme.bgColorCard))),
                    contentAlignment = Alignment.BottomEnd
                ) {
                    Text(
                        text = credSub.theme.name,
                        modifier = Modifier
                            .padding(5.dp)
                            .fillMaxWidth(),
                        fontSize = 15.sp,
                        textAlign = TextAlign.Left,
                        color = Color(android.graphics.Color.parseColor("#" + credSub.theme.fgColorTitle))
                    )
                    Image(
                        bitmap = decodedIcon,
                        contentDescription = null,
                        modifier = Modifier
                            .width(60.dp)
                            .height(60.dp)
                            .padding(top = 5.dp, end = 10.dp, bottom = 5.dp)
                    )
                }

                // Main Row
                Column (
                    Modifier
                        .fillMaxWidth(),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Image(
                        bitmap = decodedImage,
                        contentDescription = null,
                        modifier = Modifier
                            .width(120.dp)
                            .height(120.dp)
                            .padding(10.dp)
                    )
                    ShowDetailVC("First Name", credSub.firstName)
                    ShowDetailVC("Last Name", credSub.lastName)
                    ShowDetailVC("Student ID:", credSub.studentId)


                    Image(
                        //qr
                        bitmap = Utilities().generateQRCode(cs.credential.validityIdentifier).asImageBitmap(),
                        contentDescription = null,
                        modifier = Modifier
                            .width(120.dp)
                            .height(120.dp)
                            .padding(10.dp)
                    )

                    if (BarcodeType.CODE_128.isValueValid(barcode)) {
                        Barcode(
                            width = 400.dp,
                            height = 50.dp,
                            modifier = Modifier
                                .width(400.dp)
                                .height(50.dp)
                                .padding(10.dp),
                            resolutionFactor = 10, // Optionally, increase the resolution of the generated image
                            type = BarcodeType.CODE_128, // pick the type of barcode you want to render
                            value = barcode // The textual representation of this code
                        )
                    }
                }

                // Bottom Box
                Box(
                    Modifier
                        .height(20.dp)
                        .fillMaxWidth()
                        .background(Color(android.graphics.Color.parseColor("#" + credSub.theme.bgColorCard))),
                )
            }

            Button(
                onClick = { onNavigateToQrCodeScanner(cs.credential.vc.id)  },
                //colors = Color(android.graphics.Color.parseColor("#" + vc.credentialSubject.theme.bgColorCard))
                colors = ButtonDefaults.buttonColors(containerColor = Color(android.graphics.Color.parseColor("#" + credSub.theme.bgColorCard)))
            ) {
                Text("Scan Presentation QR Code")
            }
        }
    }
}

@Composable
fun ShowDetailVC(key:String, value:String){
    Text(
        modifier = Modifier.padding(top=10.dp),
        text = key,
        fontSize = 20.sp,
        fontWeight = FontWeight.Bold,
    )
    Text(
        text = value,
    )
}

@Preview(showBackground = true)
@Composable
fun DetailPreview() {

    val kpg = KeyPairGenerator.getInstance("EC")
    kpg.initialize(256)
    val keyPair = kpg.genKeyPair()

    val cs = CredentialStore(
        credential = _createVC(),
        keyPair = keyPair,
        signature = "String"
    )

    MobileWalletTheme {
        ShowDetailVC(
            cs = cs,
            onNavigateBack = {},
            onNavigateToQrCodeScanner = {}
        )
    }
}