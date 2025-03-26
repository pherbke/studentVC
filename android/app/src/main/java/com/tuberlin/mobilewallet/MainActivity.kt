package com.tuberlin.mobilewallet

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.graphics.BitmapFactory
import android.os.Bundle
import android.util.Base64
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.EnterTransition
import androidx.compose.animation.ExitTransition
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.livedata.observeAsState
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import androidx.navigation.toRoute
import com.simonsickle.compose.barcodes.Barcode
import com.simonsickle.compose.barcodes.BarcodeType
import com.tuberlin.mobilewallet.ui.theme.MobileWalletTheme
import com.tuberlin.mobilewallet.utils.Utilities
import com.tuberlin.mobilewallet.utils.WalletCredential
import kotlinx.serialization.Serializable
import java.security.KeyPairGenerator

class MainActivity : ComponentActivity() {

    //CAMERA PERSMISSION
    private val cameraPermissionRequestLauncher: ActivityResultLauncher<String> =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { isGranted: Boolean ->
            if (isGranted) {
                // Permission granted
            } else {
                // Permission denied: inform the user to enable it through settings
                Toast.makeText(
                    this,
                    "Enable camera permission to use this App",
                    Toast.LENGTH_SHORT
                ).show()
            }
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        cameraPermissionRequestLauncher.launch(Manifest.permission.CAMERA)

        setContent {
            MobileWalletTheme {
                // A surface container using the 'background' color from the theme
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    Navigation()
                }
            }
        }
    }
}

@Serializable
object Home
@Serializable
data class QrCodeScanner(val id: String? = null)
@Serializable
data class DetailView(val id: String)

@Composable
fun Navigation() {

    //Show Dialog when available
    val dialogLiveData = remember { MutableLiveData<DialogInfo>(null) }
    val dialogInfo by dialogLiveData.observeAsState(null)
    if (dialogInfo != null) {
        Dialog(dialogLiveData)
    }

    val navController = rememberNavController()
    val context = LocalContext.current
    val wallet = Wallet.getInstance(context)

    NavHost(navController, startDestination = Home, enterTransition = {EnterTransition.None} , exitTransition = {ExitTransition.None}) {
        composable<Home> {
            Overview(
                onNavigateToDetailView = {x ->
                    navController.navigate(
                        route = DetailView(id = x)
                    )
                },
                credentialStore = wallet.data,
                onNavigateToQrCodeScanner = {x ->
                    navController.navigate(route = QrCodeScanner(id = x))
                }
                )
        }
        composable<QrCodeScanner> { backStackEntry ->
            val vcId: QrCodeScanner = backStackEntry.toRoute()
            val vc = if (vcId.id != null)  wallet.getVc(vcId.id) else null

            CameraPreview(
                onNavigateBack = { navController.navigate(route = Home) },
                dialogLiveData = dialogLiveData,
                cs = vc
            )
        }
        composable<DetailView> { backStackEntry ->
            val vcId: DetailView = backStackEntry.toRoute()
            val vc = wallet.getVc(vcId.id)
            if(vc != null)
                ShowDetailVC (
                    cs = vc, //should pass the ID, but bad for preview ;)
                    onNavigateBack = {
                        navController.navigate(route = Home)
                    },
                    onNavigateToQrCodeScanner = {x ->
                        navController.navigate(
                            route = QrCodeScanner(id = x)
                        )
                    }
                )
        }
    }
}



/*
Main Page
 */

@Composable
fun Overview(
    credentialStore: LiveData<List<CredentialStore>>,
    onNavigateToDetailView: (String) -> Unit,
    onNavigateToQrCodeScanner: (String?) -> Unit,
    modifier: Modifier = Modifier
) {
    val credList by credentialStore.observeAsState(emptyList())
    Column {
        Row(
            Modifier.fillMaxWidth(),
            Arrangement.SpaceBetween
        ) {


        }
        Row(
            Modifier.fillMaxWidth(),
            Arrangement.Center
        ) {
            Text(
                text = "Overview",
                modifier = modifier.padding(10.dp),
                fontSize = 40.sp,
                fontWeight = FontWeight.Bold
            )
        }

        LazyColumn {
            items(credList) { vc ->
                IdCard(vc, onNavigateToDetailView)
            }
        }

        Row(
            Modifier.fillMaxWidth(),
            Arrangement.Center
        ) {
            val image7 = painterResource(R.drawable.plus_circle_svgrepo_com)
            val context = LocalContext.current
            Image(
                painter = image7,
                contentDescription = null,
                modifier = Modifier
                    .width(70.dp)
                    .padding(10.dp)
                    .clickable { onClickAdd({ onNavigateToQrCodeScanner(null) }, context) }
            )
        }
    }
}

@Composable
fun IdCard(cs: CredentialStore, onNavigateToDetailView: (String) -> Unit) {
    val cred = cs.credential
    // Decode the Image
    val imageBytes = Base64.decode(cred.vc.credentialSubject.image, Base64.DEFAULT)
    val decodedImage = BitmapFactory.decodeByteArray(imageBytes, 0, imageBytes.size).asImageBitmap()

    //Decode the Icon
    val iconBytes = Base64.decode(cred.vc.credentialSubject.theme.icon, Base64.DEFAULT)
    val decodedIcon = BitmapFactory.decodeByteArray(iconBytes, 0, iconBytes.size).asImageBitmap()

    val barcode = Utilities().getBarcodeString(cred.vc.credentialSubject)

    Column(
        Modifier
            .fillMaxWidth()
            .clickable { onNavigateToDetailView(cred.vc.id) }
            .padding(start = 10.dp, top = 5.dp, end = 10.dp, bottom = 5.dp)
            .clip(RoundedCornerShape(10.dp))
            .shadow(2.dp),
        Arrangement.Center
    ) {
        // Top Box
        Box(
            Modifier
                .fillMaxWidth()
                .background(Color(android.graphics.Color.parseColor("#" + cred.vc.credentialSubject.theme.bgColorCard))),
            contentAlignment = Alignment.BottomEnd
        ) {
            Text(
                text = cred.vc.credentialSubject.theme.name,
                modifier = Modifier
                    .padding(5.dp)
                    .fillMaxWidth(),
                fontSize = 15.sp,
                textAlign = TextAlign.Left,
                color = Color(android.graphics.Color.parseColor("#" + cred.vc.credentialSubject.theme.fgColorTitle))
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
        Row (

        ) {
            Image(
                bitmap = decodedImage,
                contentDescription = null,
                modifier = Modifier
                    .width(100.dp)
                    .height(100.dp)
                    .padding(10.dp, 10.dp, 10.dp, 10.dp)
            )
            Column {
                Row(modifier = Modifier.height(IntrinsicSize.Max)){
                    Text(
                        text = cred.vc.credentialSubject.firstName + "\n"+
                                cred.vc.credentialSubject.lastName + "\n"+
                                cred.vc.credentialSubject.studentId,
                        modifier = Modifier.padding(10.dp),
                        fontSize = 20.sp,
                        textAlign = TextAlign.Left
                    )
                    Image(
                        //qr
                        bitmap = Utilities().generateQRCode(cred.validityIdentifier).asImageBitmap(),
                        contentDescription = null,
                        modifier = Modifier.padding(10.dp)
                    )
                }

                if (BarcodeType.CODE_128.isValueValid(barcode)) {
                    Barcode(
                        width = 450.dp,
                        height = 30.dp,
                        modifier = Modifier
                            .width(450.dp)
                            .height(30.dp)
                            .padding(10.dp),
                        resolutionFactor = 10, // Optionally, increase the resolution of the generated image
                        type = BarcodeType.CODE_128, // pick the type of barcode you want to render
                        value = barcode // The textual representation of this code
                    )
                }


            }
        }

        // Bottom Box
        Box(
            Modifier
                .height(20.dp)
                .fillMaxWidth()
                .background(Color(android.graphics.Color.parseColor("#" + cred.vc.credentialSubject.theme.bgColorCard))),
        )
    }
}

@Preview(showBackground = true)
@Composable
fun OverviewPreview() {

    val kpg = KeyPairGenerator.getInstance("EC")
    kpg.initialize(256)
    val keyPair = kpg.genKeyPair()

    val walletData = MutableLiveData(listOf(
        CredentialStore(
            credential = _createVC(),
            keyPair = keyPair,
            signature = ""
        )
    ))


    MobileWalletTheme {
        Overview(
            walletData,
            onNavigateToDetailView = {},
            onNavigateToQrCodeScanner = {  },
        )
    }
}

fun _createVC(): WalletCredential {
    val vc = WalletCredential.VerifiedCredential(
        id = "urn:uuid:181ac538-e53c-4629-a52a-ca250f9021b9",
        issuer = "did:key:zXwpRkGUVewNMEMKkQ1Dp4AGB5ft8r48YVfMeercb784Z8fjLu3amoSoPtcDuBi43QBq9h16fihKcQbJrhpz9j5UYFpc",
        issuanceDate = "2025-01-01T17:09:16.158056",
        validFrom = "2025-01-01T17:09:16.158066",
        credentialSubject = WalletCredential.VerifiedCredential.CredentialSubject(
            id = "did:key:zXwpSa56ESFsQF2xnp3ZmVuzPKyNdpxmL528WabAy3EW9zMDmiNPm4n4ts2yNPphF2zrEMhm3G5fJ6eAKEBNP7jowx8k",
            firstName = "Maxi",
            lastName = "Musterfrau",
            image = "iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAYAAADgdz34AAAABHNCSVQICAgIfAhkiAAAAAlwSFlzAAAApgAAAKYB3X3/OAAAABl0RVh0U29mdHdhcmUAd3d3Lmlua3NjYXBlLm9yZ5vuPBoAAANCSURBVEiJtZZPbBtFFMZ/M7ubXdtdb1xSFyeilBapySVU8h8OoFaooFSqiihIVIpQBKci6KEg9Q6H9kovIHoCIVQJJCKE1ENFjnAgcaSGC6rEnxBwA04Tx43t2FnvDAfjkNibxgHxnWb2e/u992bee7tCa00YFsffekFY+nUzFtjW0LrvjRXrCDIAaPLlW0nHL0SsZtVoaF98mLrx3pdhOqLtYPHChahZcYYO7KvPFxvRl5XPp1sN3adWiD1ZAqD6XYK1b/dvE5IWryTt2udLFedwc1+9kLp+vbbpoDh+6TklxBeAi9TL0taeWpdmZzQDry0AcO+jQ12RyohqqoYoo8RDwJrU+qXkjWtfi8Xxt58BdQuwQs9qC/afLwCw8tnQbqYAPsgxE1S6F3EAIXux2oQFKm0ihMsOF71dHYx+f3NND68ghCu1YIoePPQN1pGRABkJ6Bus96CutRZMydTl+TvuiRW1m3n0eDl0vRPcEysqdXn+jsQPsrHMquGeXEaY4Yk4wxWcY5V/9scqOMOVUFthatyTy8QyqwZ+kDURKoMWxNKr2EeqVKcTNOajqKoBgOE28U4tdQl5p5bwCw7BWquaZSzAPlwjlithJtp3pTImSqQRrb2Z8PHGigD4RZuNX6JYj6wj7O4TFLbCO/Mn/m8R+h6rYSUb3ekokRY6f/YukArN979jcW+V/S8g0eT/N3VN3kTqWbQ428m9/8k0P/1aIhF36PccEl6EhOcAUCrXKZXXWS3XKd2vc/TRBG9O5ELC17MmWubD2nKhUKZa26Ba2+D3P+4/MNCFwg59oWVeYhkzgN/JDR8deKBoD7Y+ljEjGZ0sosXVTvbc6RHirr2reNy1OXd6pJsQ+gqjk8VWFYmHrwBzW/n+uMPFiRwHB2I7ih8ciHFxIkd/3Omk5tCDV1t+2nNu5sxxpDFNx+huNhVT3/zMDz8usXC3ddaHBj1GHj/As08fwTS7Kt1HBTmyN29vdwAw+/wbwLVOJ3uAD1wi/dUH7Qei66PfyuRj4Ik9is+hglfbkbfR3cnZm7chlUWLdwmprtCohX4HUtlOcQjLYCu+fzGJH2QRKvP3UNz8bWk1qMxjGTOMThZ3kvgLI5AzFfo379UAAAAASUVORK5CYII=",
            studentId = "123456",
            theme = WalletCredential.VerifiedCredential.CredentialSubject.Theme(
                name = "Technische Universität Berlin",
                icon = "iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAYAAADgdz34AAAABHNCSVQICAgIfAhkiAAAAAlwSFlzAAAApgAAAKYB3X3/OAAAABl0RVh0U29mdHdhcmUAd3d3Lmlua3NjYXBlLm9yZ5vuPBoAAANCSURBVEiJtZZPbBtFFMZ/M7ubXdtdb1xSFyeilBapySVU8h8OoFaooFSqiihIVIpQBKci6KEg9Q6H9kovIHoCIVQJJCKE1ENFjnAgcaSGC6rEnxBwA04Tx43t2FnvDAfjkNibxgHxnWb2e/u992bee7tCa00YFsffekFY+nUzFtjW0LrvjRXrCDIAaPLlW0nHL0SsZtVoaF98mLrx3pdhOqLtYPHChahZcYYO7KvPFxvRl5XPp1sN3adWiD1ZAqD6XYK1b/dvE5IWryTt2udLFedwc1+9kLp+vbbpoDh+6TklxBeAi9TL0taeWpdmZzQDry0AcO+jQ12RyohqqoYoo8RDwJrU+qXkjWtfi8Xxt58BdQuwQs9qC/afLwCw8tnQbqYAPsgxE1S6F3EAIXux2oQFKm0ihMsOF71dHYx+f3NND68ghCu1YIoePPQN1pGRABkJ6Bus96CutRZMydTl+TvuiRW1m3n0eDl0vRPcEysqdXn+jsQPsrHMquGeXEaY4Yk4wxWcY5V/9scqOMOVUFthatyTy8QyqwZ+kDURKoMWxNKr2EeqVKcTNOajqKoBgOE28U4tdQl5p5bwCw7BWquaZSzAPlwjlithJtp3pTImSqQRrb2Z8PHGigD4RZuNX6JYj6wj7O4TFLbCO/Mn/m8R+h6rYSUb3ekokRY6f/YukArN979jcW+V/S8g0eT/N3VN3kTqWbQ428m9/8k0P/1aIhF36PccEl6EhOcAUCrXKZXXWS3XKd2vc/TRBG9O5ELC17MmWubD2nKhUKZa26Ba2+D3P+4/MNCFwg59oWVeYhkzgN/JDR8deKBoD7Y+ljEjGZ0sosXVTvbc6RHirr2reNy1OXd6pJsQ+gqjk8VWFYmHrwBzW/n+uMPFiRwHB2I7ih8ciHFxIkd/3Omk5tCDV1t+2nNu5sxxpDFNx+huNhVT3/zMDz8usXC3ddaHBj1GHj/As08fwTS7Kt1HBTmyN29vdwAw+/wbwLVOJ3uAD1wi/dUH7Qei66PfyuRj4Ik9is+hglfbkbfR3cnZm7chlUWLdwmprtCohX4HUtlOcQjLYCu+fzGJH2QRKvP3UNz8bWk1qMxjGTOMThZ3kvgLI5AzFfo379UAAAAASUVORK5CYII=",
                bgColorCard = "C40D1E",
                bgColorSectionTop = "C40D1E",
                bgColorSectionBot = "FFFFFF",
                fgColorTitle = "FFFFFF"
            ),
            issuanceCount = "1",
            studentIdPrefix = "TODO()"
        ),
        type = listOf(""),
        credentialSchema = WalletCredential.VerifiedCredential.CredentialSchema(type = "", id = ""),
        expirationDate = "2025-01-01T18:09:16.158069",
        context = listOf(""),
    )
    return WalletCredential(
        iat = 1,
        iss = "TODO()",
        sub = "TODO()",
        exp = 1,
        nbf = 1,
        jti = "TODO()",
        vc = vc,
        nonce = "TODO()",
        signedNonce = "TODO()",
        bbsDpk = "TODO()",
        validityIdentifier = "TODO()",
        totalMessages = 1,
    )
}

@Preview(showBackground = true)
@Composable
fun IdCardPreview() {

    val kpg = KeyPairGenerator.getInstance("EC")
    kpg.initialize(256)
    val keyPair = kpg.genKeyPair()

    val cs = CredentialStore(
        credential = _createVC(),
        keyPair = keyPair,
        signature = "String"
    )

    IdCard(cs, {})
}



fun onClickAdd(onNavigateToQrCodeScanner: () -> Unit, context: Context) {

    when {
        ContextCompat.checkSelfPermission(
            context,
            Manifest.permission.CAMERA
        ) == PackageManager.PERMISSION_GRANTED -> {
            // Permission is granted, open CameraView
            onNavigateToQrCodeScanner()
        }

        else -> {
            // Permission is not granted: request it
            Toast.makeText(
                context,
                "Enable camera permission to use this feature",
                Toast.LENGTH_SHORT
            ).show()
        }
    }

}
