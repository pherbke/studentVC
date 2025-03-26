package com.tuberlin.mobilewallet.qrHandler

import android.content.Context
import android.net.Uri
import android.util.Base64
import android.util.Log
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Warning
import androidx.lifecycle.MutableLiveData
import com.google.gson.Gson
import com.google.gson.annotations.SerializedName
import com.google.gson.reflect.TypeToken
import com.tuberlin.mobilewallet.CredentialStore
import com.tuberlin.mobilewallet.DialogInfo
import com.tuberlin.mobilewallet.rust.uniffi.bbs_core.GenerateProofRequest
import io.jsonwebtoken.Jwts
import okhttp3.Call
import okhttp3.Callback
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import org.json.JSONObject
import java.io.IOException
import java.util.concurrent.ExecutionException


private const val TAG = "VerifierHandler"

// handle the QR Code URL --> .../verifier/presentation-request
fun requestPresentationRequest(
    barcodeUrl: String,
    context: Context,
    dialogLiveData: MutableLiveData<DialogInfo>,
    cs: CredentialStore
){

    val client = getClient(false)

    val request = Request.Builder()
        .url(barcodeUrl)
        .post("".toRequestBody(null))
        .build()

    client.newCall(request).enqueue(object : Callback {
        override fun onFailure(call: Call, e: IOException) {
            e.printStackTrace()
            Log.e(TAG, "Client Call Error",e)
        }

        override fun onResponse(call: Call, response: Response) {

            // Handle success, get Redirect URL
            if (response.header("Location") != null) {

                Log.i(TAG, "Received Redirect:\n"+response.header("Location"))

                try {

                    val urlRedirectString: String = response.header("Location")!!
                    val responseUri = Uri.parse(urlRedirectString).encodedQuery
                        ?.split("&")
                        ?.first{it.startsWith("response_uri=")}
                        ?.split("=")
                        ?.get(1)
                    val presentationDefinition = Uri.parse(urlRedirectString).encodedQuery
                        ?.split("&")
                        ?.first{it.startsWith("presentation_definition=")}
                        ?.split("=")
                        ?.get(1)

                    if(responseUri == null){
                        throw Exception("ResponseUri is empty\n$urlRedirectString")
                    }
                    if(presentationDefinition == null){
                        throw Exception("presentationDefinition is empty\n$urlRedirectString")
                    }


                    requestCredentialPresentation(responseUri, presentationDefinition, context, dialogLiveData, cs)

                } catch (exc: Exception) {
                    Log.e(TAG, "Redirect Link Error\n"+response.header("Location"), exc)
                }


            } else {
                Log.e(TAG, "No expected Redirect received!\n$response")
            }
        }
    })

}


private fun getMandatoryFields(presentationDefinitionEnc: String): Array<String> {

    data class PresentationDefinition(
        @SerializedName("mandatory_fields") var mandatoryFields: Array<String>
    )

    var mandatoryFields = arrayOf<String>()
    var presentationDefinitionString = Uri.decode(presentationDefinitionEnc)
    try {
        presentationDefinitionString = presentationDefinitionString
            .replace(":+",":")
            .replace(",+",",")
        val presentationDefinition =  Gson().fromJson(presentationDefinitionString, PresentationDefinition::class.java)
        mandatoryFields = presentationDefinition.mandatoryFields
    } catch (e: ExecutionException){
        Log.e(TAG, "Error while getting Mandatory Fields\n$presentationDefinitionString",e)
    }
    return mandatoryFields
}

private fun requestCredentialPresentation(
    urlEnc: String,
    presentationDefinitionEnc: String,
    context: Context,
    dialogLiveData: MutableLiveData<DialogInfo>,
    cs: CredentialStore
){
    // decode the parameter
    val url = Uri.decode(urlEnc)

    //get the mandatory fields
    val mandatoryFields = getMandatoryFields(presentationDefinitionEnc)

    Log.i(TAG, "RequestCredentialPresentation \nRequest URL: \n$url\nMandatory Fields:\n${mandatoryFields.joinToString(" ")}")

    val client = getClient()

    val urlBuilder: HttpUrl.Builder? = (url).toHttpUrlOrNull()?.newBuilder()

    //create the Body:
    // e.g. "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJ2ZXJpZmlhYmxlX2NyZWRlbnRpYWwiOnsibm9uY2UiOiJFK0FTS1wvTU91TGZFM1lza3JKNEt2VDNMak9BUU1lRmNoaGs2bU41ZHllST0iLCJwcm9vZiI6IkFBQUVmSVwvTkNtbHp3Z0grbHo2K1IreVwvd3JRdXdxN0RkRGI1dk8rSGRMSnFnRThubHk0bUJOTDFIR1VEdkNuc0k2VjUyS1JMd1BXWDdpNEdlNkpmdk12aWROZ3hNU3hzVlVtcVRHRkV4T3FcL3pEVlhCNnBFaCtQNG0zaStvcHNwZU1ISkk1SU1aTlFydTRaZTRmYlU0Njd6ZmNjd1Q3QmJNS0FRYlBtM29ReGUyaUNUWW1PWHpDbXRrZkpJQVljNjdhTHhYQUFBQUhTMHgyOUhYYXFmSVArbHJ5XC9paEtQeGtOS2o5USt1MjBUaHlBZkNkN2VDakZjdGp4VmxoUXAzMThaemo4RjVyNGNBQUFBQ09XNHFydHRlTElHWWxoYW9tRzB3cFFES3hkK1dlXC9TVCtDV2ZtSmEwRks0eWVSa0UwT0lubXNXa045c3ZXMG82WCs1NUVZU1F0NEZQNHVlMFRmNXV0Sk5CUjdLeFJIdE1LTlNyZEFwNjBLdmxyVE1PSWJHOTdkOTg3RUVzenhcLytoQXJYR25QVklTUktvOE1cL1ByS29tUUFBQUJvN09rRzVkQVA4N0l6dG95bUpkYTRZOUJjNHhmc1dVbEZLUVR3cytjXC9kMFZ2eWVXcEx2ZktUQ2dqVzE4bVpuZmZpb0FDWHNGSUhDOWQxU05Fdjh0ZUNKNXRhTmc5b1A1ZHhOMWFDclBPd0dPVmwwN21WdkFcL2ZOalZnanNYRTE5Z0xxVTJJMDFzSktHanJhTmxuOTJwSStcL3gzR2RudWxmNXQ4WjcwWHA3a2dUcXl2XC9zY2N0eXJnQ1VCa1BuNzYxMldkVlhlNkJ0R1dseEFkTnZlYkNnWVpxandwMU1aOEx5XC84VjIrNENnRDM5SFoyNmI2Ymg3V0MrblZMSFwveERETWxhQVd4Yk9ldlJDdU1pQjNVUGYwVkZaRW9wZUZmclBYUU84ZldrTDNvT1N3YjNFNzRWRXd5eUlwN05wVEg3M2Q0R1NFUlVLTVNoYVwvdEYraUhNbDhyVHN3dllybDIrR1k1UzJoMFBySkQ1U09WVGZ3bUg0VjM4clI3RThUUHBDVlFZbjJCM3hLcEY5b09tZFVzXC9XemNoRVpMRCtJNDBrVW4rbmpuaDZiV08yMmR2b2pMZlwvVkNWZnJ5T3hINE9qenk2Uk4zMnpXWlhUaG82eW84dXVhTEJNUlBJYkw4M0FcL3RVTUhqclpmNTc3TTltMkVabituZ2Z5R1ZyeGtYU0FGcm5DWWloMzh1R2FNTGk2YUR6WW5EQnAyNWMrM0ZDREZ0Z2cxTVFFTnBqMVdcL21VSHMxVXZEemdZRU1NUEtiYnhrdStpYnhLN1RMMk8xYnpTdUVwRjdZVStLQ2ZuRXJaYW5tYnZKRVwvYXV0NzFYUWw2Q2F0YzFQR1doRnJDZDV3NHMrUjVQbUZScjE0WU8xaWtCRU9ETFFCRGJpN083SXczWnI5RkVOOEQwWmxTYjVjQWZhTnFKSXJrY0RWXC9sVFhxZGtVNE1DNEo4amQ1MGtjTFdpV0VXWjNnZ3dET3pQNUJGVWZDSzhSbktYRlIrYVNkSEhQalJ1OUJKajk4NWMrZ2c0OURuRTJCQjNITFN6QWE3NkZQNXhaaVhGUmZqYmVuenZLY3E1QjhhNEdPRXd3RlZBeUtmMlNmNkJqRDZcL3RkbWNqdFJsNkJRaGRFb3AwSms3ZFdMYVlHUnRXT3k3a3Y5Tm9OS0Z3YmVFUW94WHhxeW1GRGV1b09wK0g1RVhGeHZXVWZRSmFwT1wvN0lIeDNIYkdPWmxxVHFkU2E1cmxVSkdpYnBPOHlLNitGMWtWTmphV0M0WWR3NmptbWtoRW12cSs0VGxISk5zMVRvY0lhSGNzN2o1VDczbFhQbkREQ3ZneE9lUEV4blBBVFN3TzNoaXdKRGJMTDdHNm1peDNhUW1NbVFJaWtqMmRTb3JHXC85QndpUnRQdmNBZDl4Yit3TTlkK015aFZnYVNFazZCN01cLys0Q296b05reDlHNHBTdzhPWHNIK3FQdXpjMjJwSWY5ZmJoYkFBQUFDUUFBQUFCdjlNUEYyZnFaZGRnWjB3XC9ycEdwNHZlaXZzMzdqakY0aGU4eElZR2Z3M3dBQUFBTTlLSjFrbnA3Ykh1TkFjSHlFQThveE9IeVFOcXQ4N3lGYUxlR3pCRGg3dEFBQUFBWlVqXC9UTFpnWjJcL0JtbVhsYUtSMEMweElPYUNoYVdVSFN1ekYrWnJxaElvUUFBQUFjeHliMGNUU2VGdVI4dHRScjFGckUyZlZtNUNWTFFwYkNiNFMrK2trVjBSZ0FBQUFnekZMbHZObUVTcWEzNjFKTWFpY0tSVmM5V1R2bFU5ZmdkMVpVT25cLzdOVndBQUFBa25NY0JXREdtQUFYZ1dsSzlEVWFMOXpCMWduc1RobHI0OVRhbHBDV2Z3a3dBQUFBbzgyQnVFMzJRblRCbzBYY1pmTDhqSHdqNEZSMUprUVB0cDdpUFN0K3I5eEFBQUFBNFZBWVdnTlp2ZVNxRm5ZK2hVNHhcL0h5eklpdllpUVpFZGZ4UTk0eXJOY3pRQUFBQmtjUzlVaTRXbUVuRG4yNnF4UUllb0RJc04zXC9XaEFsUnR1YlJVeHVUeEtqUT09IiwidmFsdWVzIjp7InZjIjp7ImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImZpcnN0TmFtZSI6Ik1heGlsMXVrNSJ9LCJleHBpcmF0aW9uRGF0ZSI6IjIwMjUtMDEtMTdUMTM6MTc6NDQuMTQwMjg2In0sIm5vbmNlIjoiZHprNzVkMGplNGNsdXJ5bzhvYmoiLCJiYnNfZHBrIjoib0FSdVFvS21iS1RBTUpoWGRKSXdWR2FuNXp3VnRXdEVsVXhaSitGYnBqV0g1Sk5wMzNsUUtwUjQyWkdXOHpuQUJ1NGVBMVdGSVFjOWsxc2hDczQ2dyszNGpoeVRxeGRQZWVFXC9ycTZtdlByaXkyRU9cL1B2aTJ4UmlETFRqOUZmcCIsImlzcyI6ImRpZDprZXk6elh3cFJFS0RmUFhXOGNOR041S015ZXM5M1ZnVlFOTlFobU1Ca0xtQlByNU1CV21DRGd0RDhVTUhROGpjc2pYZG1CZzJMRFRCVjc2eFlvekRqVGo4eEdQcXZaU1YiLCJ2YWxpZGl0eV9pZGVudGlmaWVyIjoiaHR0cHM6XC9cLzE5Mi4xNjguNTAuMTM5OjgwODBcL3ZhbGlkYXRlXC9pc3ZhbGlkXC9jazkzNTVmdTN3N2Vlbjhkb3F5dTBseWZ5YzBrcW0zZHZkeTNkbWJhbHA0a2YzcTFlbyIsInNpZ25lZF9ub25jZSI6ImV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUp1YjI1alpTSTZJbVI2YXpjMVpEQnFaVFJqYkhWeWVXODRiMkpxSW4wLl9sVlVOX3JmWXhoY21lWVJ2eVp4MGxudm9QODRrbmdPWXYxZWZDUWRKYUswTmRlNk9PQ2pRZ2FGcC1ZdnFvRFppOVY2b1VKYnEtOTk1Tm9rZXEybFNBIiwic3ViIjoiZGlkOmtleTp6WHdwUlJKV3JUZm51V3hmNFhLdjZVYWJjbzhKQmdqV29yWUdwM0F2S1FiZ1luTmcyUzVuUjY1WWpoaldEZlJXRFljUTRFNDhBWlFEeW9xdWZyVHRCY0o1aEtkVyIsInRvdGFsX21lc3NhZ2VzIjozM30sInByb29mX3JlcSI6IkFBQUFCUUFDQUVmSm9BUnVRb0ttYktUQU1KaFhkSkl3VkdhbjV6d1Z0V3RFbFV4WkorRmJwaldINUpOcDMzbFFLcFI0MlpHVzh6bkFCdTRlQTFXRklRYzlrMXNoQ3M0NncrMzRqaHlUcXhkUGVlRVwvcnE2bXZQcml5MkVPXC9QdmkyeFJpRExUajlGZnBzVVlsMDA0RHRtWFZPZ3E3S3BMSkw5RHlLdUQ3NnRcL051Q0pLZnNpZTgwbHdQd01CeHhhcHJ4TG9DakZEMk1PRUFBQUFJWWZrQlJKQ1BzaE1xQVwvSGZVRXRVUmJ3UytFNmVUQmRVR1lJZXBhU2RyWWFpN3lTUW9SWmtzSTVvYWp4VVdvZGJyQU5sZVZqZDBRYzhwamErN0NzK1VuT3RQMitrTXQ1a0pOYWFBTkhNb1lBYXZvYjZhVEZUVmN1d3JpYzA2OU9uSzdHVnRVUEZQVjR4NVRVbUdLZkgzZm9SWlk2aGdhMHVtQlBzRDl1eFhhdHYrRjY4K0NEYzBzbFpLOU9pbE90NzRHOEx1bllwdVBnVjBHb1ZFYmFnbm4zeFdsRG00N0xHN0k1RW42YlJTckpNdFkxaWxGYytYRVdxMWxUc0lMK1BMbGw3ZlwvK3JzMmRJVEg0aWVGSjlBK0FPMnNDNmNweVVhb0tOcmtacFRKRng5OElPYmpQYkZNYWx5T0JCVjhWbjRqaTRkZ0xSc1lRTFhZcmlSWnk1NGNNcFNva1N0M1R2UzZoaE55b25DcXMycjY0RnNpTEdaa0hUeU9WXC9TVlVXcmZORlwvS1pycUI3UVJ0aSsrZFwvNVNqR2xhemEyQlhDazl3d0FjYmFBQWRwZ2FtT2Y3cGVGT001MlpheFBjMVNyTFhwelR6Y2tQc0FUMnVMN09iejVXc1NqdVV4OXpCa25QR1IxN1kzVzRXT25aS1wvaENjMzduRVhYNDJwRDl1UTY2cTM1MzZJUTlRTVdlQ0szTE5EMnJHanpuZmt6WGJ0MXBkYW5IbGtJekpvRCs5UVJKS0xEQnR4ZzlJOEdaZXBxSmZsSmY5a3YxVHI2WGtuakRMbjAzZ2Q4bHZJQ01uZFBhK09aeTBsSHRpU1ZUd2ZtRnJ6NTZNOFozUkNWRE9WaXFVb1k0UW1QOUkyeFg0ZlBLdCsxamRkdUtxYnV0azNDTktPNE1waDdlVUhFa3lEQXZyRzZOZXFSa0k4T28wZkU1alk5OXJ1MG9XZmo0TzBTTXdxdmNJeHVBaVgzVXJ5dDcxUHFaVDYzSTV0aXE2OEtWSW9XRzJ4NG1WNUZ2KzI1WmZJSGdFd3dxZmdSRlNham9TcWg0M2hoR05jbU04TEkzSGRsK0V6YjlVN0VjNUI5RmhDZmpPQmgrRjFCWHZIb2FES0ZmdEtOS3ZUNVZWOXU4aVRcLzRQRXZiNHNMcW9Pc1ZsY05jaUhlOUtaNjhEUGYwWlB1SUJxa29ZWEl2SjlrNm5qRmZBRzJBM21HQlMrV0FQV2k4aEVPM1JkK0tvNXBXRTFVeVRLRldvMENQZWJNRWxLa05vQUFVMzNkdTFrWFpnT0JySjB5SVFnTUlVVGV1UDJZQW55U3V2REs1YnJ2MGZ0U0VxNUo2Y1gzM0xrektPNlhxcHY4aGFWeGtnTENxbjV2MVwvUnRrdUpvOFA3SUtDbEtnNWo3OCtGdElqYnlKdlRzS2hOMXVjSlJ0OHFZUUNNbHF4eEo3NWxJSHlEZm84TFF3NDN5c0J5R2FudVMyTlhyTnFTUVN4MFdtbDdNVk1EN3VPUlNcL0E4dGw0OEp0UCthbzhOVnVEK1hSc1pqb3pla2pKeTIxWFhTcExLcVwvVFhFdkdFekxyME84VEFcL1NiQk82amtHMWJ4Mk1zZmFrNTFod0NFU3ZZZjRNY0hnWTU3Y0VDV090ZlpxNSs0ajd6WDZpXC9Xc1VRY1N3XC9cLzlcLzM5UlByc3dqb3FXM1JNcThOREF4d2hOamJXNWVIcFdZOUlwTWc1bG5kM252eVFTQVlpK3UweVRWMFZ6cUpMeXhoYTZIemFaR1dLbjR4c3Y3Y2E3Ymhsak1kVDdLQ3JKb2lpTHQzTmxad1lsbXlnSkd4K1NDb0I0cDk3TWtac3BTYXBqZkhtMTM5MDNnSjM0WXo0TitVb01ZMUw1YTN5SjdkTUNzeEt3YnNoUkZCSExYc0dHOHVLZnZmQ3FxTzdRY2U2djRIU21YTFNXZDN4VkRITm54ZFd6MEgxVWRYN3M0Kzc2WXRQUGRqbDV5UEh6a2pUR00xWjk5MWV3UVFlYUV3dDgwMVJrTnNCSlFlR0FVaHBEcDNZNlZqXC8yZDF0d2F3Z1hBcVFxSTNyUEFEZ0tmZk5ZMFlaT0hLSzF4STlraGpheDlUSVdER1FKT1doMFV6WGo3QnZRV1g1UzlRNnVhbjdkdGFQOEE0cEJMNEt2eitUTTNQWkRDdXhOQmR6ekRETSs4ZlBCZzUxaWhPSFhyeElXYTU1eGIyQ25IbWV3N243djROdThjcjk5b3laYzdBK004K0tMeUFIZ2pKTFNmTUtjdGE0UVUrZ2UzaFMraUF1UGZUeUsxTE1haTgxSUtDYnVnb2s1azlxOXpFMXJwWXVwU3JRMExzTXpuZDA3Um9wWUZwSlwvWFZBbmR5RVlxd2U5Wm1ucmcrb013VHFRTEZ1eDJ6am5kRXhFRlN2RkFOelpxSjdNWXhkVEowTkhEK0YrMmFJNklVN0xqMzhcL1ZjNjlHQm5tYkNQYStzTXc3S1RQRE9HRSszNXRIbVNtOElQTzlFT0lUMWxqaTF0VDB2T09HeGRmcmp1XC9HNEVhWG16SFdsTmY1blQ4U1RGT0xrYk5kcXlxYTRUaitEa0NtUFwvcUdYUWJOT1F0SFJaeEcrYWh4UEZQXC9ETklHNWNmRWhKT0pvY2h0ZlZyTkVzT2F1MmRpVHUzcHZBR3FaOEw0MTgzc1crSjFZQTRnK05aZ2hlRndJTCtpT2x0aVFlYXlMXC95OFdOY0o3TUFEWmk4cEF2U2lZcG84Wmk0NENReXpzNldJS1lBK0RyOFNydDVuMUQyall3TnVrNFdvZmw0dEhhaUR2a0ROWjNlSHVjNFE9PSJ9fQ.ww-PAY8i03Xf9ZBAX40pqzQh7ara10Tvq0IZ4MXaTJ6YSNwGuxscLTA2f1Bh1FkswnTMpCuth644iSX_RKqYIA"
    val vpToken = createVpJwt(mandatoryFields, context, cs)

    urlBuilder?.addQueryParameter("vp_token", vpToken)
    urlBuilder?.addQueryParameter("presentation_submission", "presentation_submission")

    val request = Request.Builder()
        .url(urlBuilder?.build().toString())
        .post("".toRequestBody("application/x-www-form-urlencoded; charset=utf-8".toMediaTypeOrNull()))
        .build()

    client.newCall(request).enqueue(object : Callback {
        override fun onFailure(call: Call, e: IOException) {
            e.printStackTrace()
        }

        override fun onResponse(call: Call, response: Response) {
            // Process the response data

            val result = response.body?.string() ?: ""
            Log.i(TAG, "requestCredentialPresentation Response:\n$result")

            if(result.contains("Access token is valid")){
                dialogLiveData.postValue(DialogInfo(
                    "Presentation Success",
                    "Card has been successfully presented",
                    Icons.Default.Check))
            } else {
                dialogLiveData.postValue(DialogInfo(
                    "Presentation Failed",
                    "Card is not Valid",
                    Icons.Default.Warning))
            }

        }
    })
}

fun createVpJwt(mandatoryFields: Array<String>, context: Context, cs: CredentialStore): String? {

    var claims:Map<String, Any> = mapOf()
    try {
        claims = mapOf(
            "verifiable_credential" to createVerifiableCredentialJson(cs, mandatoryFields),
        )
    } catch (e: Exception) {
        Log.e(TAG, "Error in Creating Verifiable Credentials",e)
    }


    return Jwts.builder()
        .setClaims(claims)
        .setHeaderParam("typ","JWT")
        .signWith(cs.keyPair.private)
        .compact()
}

fun flattenJSON(
    json: Map<String, Any>,
    prefix: String = "",
    separator: String = "."
): Map<String, Any> {
    val result = mutableMapOf<String, Any>()

    for ((key, value) in json) {
        val newKey = if (prefix.isEmpty()) key else "$prefix$separator$key"

        when (value) {
            is Map<*, *> -> {
                @Suppress("UNCHECKED_CAST")
                val nested = flattenJSON(value as Map<String, Any>, prefix = newKey, separator = separator)
                result.putAll(nested)
            }
            is List<*> -> {
                value.forEachIndexed { index, element ->
                    if (element is Map<*, *>) {
                        @Suppress("UNCHECKED_CAST")
                        val nested = flattenJSON(element as Map<String, Any>, prefix = "$newKey$separator$index", separator = separator)
                        result.putAll(nested)
                    } else {
                        result["$newKey$separator$index"] = element ?: ""
                    }
                }
            }
            else -> {
                result[newKey] = value
            }
        }
    }

    return result
}

fun unflattenJSON(
    dict: Map<String, Any>,
    separator: String = "."
): Map<String, Any> {
    val result = mutableMapOf<String, Any>()

    for ((key, value) in dict) {
        val components = key.split(separator)
        insertValue(components, value, result)
    }

    // Convert numeric-keyed dictionaries to arrays
    for ((key, value) in result) {
        if (value is Map<*, *>) {
            @Suppress("UNCHECKED_CAST")
            result[key] = convertToArrayIfNeeded(value as Map<String, Any>)
        }
    }

    return result
}

private fun insertValue(
    components: List<String>,
    value: Any,
    dict: MutableMap<String, Any>
) {
    val firstComponent = components.firstOrNull() ?: return

    if (components.size == 1) {
        dict[firstComponent] = value
    } else {
        val subDict = dict.getOrPut(firstComponent) { mutableMapOf<String, Any>() }
        if (subDict is MutableMap<*, *>) {
            @Suppress("UNCHECKED_CAST")
            insertValue(components.drop(1), value, subDict as MutableMap<String, Any>)
        }
    }
}

private fun convertToArrayIfNeeded(dict: Map<String, Any>): Any {
    val keys = dict.keys.sortedBy { it.toIntOrNull() ?: Int.MAX_VALUE }

    return if (keys.all { it.toIntOrNull() != null }) {
        keys.map { key ->
            val value = dict[key]
            if (value is Map<*, *>) {
                @Suppress("UNCHECKED_CAST")
                convertToArrayIfNeeded(value as Map<String, Any>)
            } else {
                value
            }
        }
    } else {
        dict.mapValues { (_, value) ->
            if (value is Map<*, *>) {
                @Suppress("UNCHECKED_CAST")
                convertToArrayIfNeeded(value as Map<String, Any>)
            } else {
                value
            }
        }
    }
}


fun createVerifiableCredentialJson(cs: CredentialStore, mandatoryFields: Array<String>): Any {
    val dpkBytes = Base64.decode(cs.credential.bbsDpk, Base64.DEFAULT)
    val signatureBytes = Base64.decode(cs.signature, Base64.DEFAULT)

    // Create a Flat JSON from our Credentials, to have the same keys as mandatoryFields
    val credJson = Gson().toJson(cs.credential)
    val credMap = Gson().fromJson(credJson, object: TypeToken<Map<String, Any>>(){})
    val flatJWT = flattenJSON(credMap)


    val sortedKeys = flatJWT.keys.sorted()
    val revealedIndices = sortedKeys.mapIndexedNotNull { index, key ->
        val isMandatoryField = mandatoryFields.any { mandatoryField ->
            key.startsWith("$mandatoryField.") || key == mandatoryField
        }
        if (isMandatoryField || key.startsWith("vc.credentialSubject.firstName")) {
            index.toULong()
        } else null
    }

    val messages:  List<String> = try {
        sortedKeys.map { key ->
            val singlePairDict = mapOf(key to flatJWT[key]!!)
            val jsonData = JSONObject(singlePairDict).toString()
            jsonData
                .replaceFirst(":", ": ")
                .replace("\\/","/")
        }
    } catch (e: Exception) {
        Log.e(TAG, "Error in sortingKeys",e)
        return listOf("")
    }

    if (messages.size != sortedKeys.size) {
        Log.e(TAG, "Couldn't create presentation object")
    }

    if (messages.size != cs.credential.totalMessages.toInt()) {
        Log.e(TAG, "Message Number does not fit: current:(${messages.size}), expected(${cs.credential.totalMessages})")
    }

    val extractedValues = revealedIndices.associate { index ->
        val key = sortedKeys[index.toInt()]
        key to flatJWT[key]!!
    }
    val presentedValues = unflattenJSON(extractedValues)

    val proof = GenerateProofRequest(
        pubKeyBytes = dpkBytes,
        signatureBytes = signatureBytes,
        revealedIndices = revealedIndices,
        messages = messages
    ).generateProof()

    Log.i(TAG, "verifiable_credential.values : "+JSONObject(presentedValues))

    val verifiableCredentialObject = JSONObject()
    verifiableCredentialObject.put("nonce", Base64.encodeToString(proof.nonceBytes, Base64.NO_WRAP))
    verifiableCredentialObject.put("proof", Base64.encodeToString(proof.proofBytes, Base64.NO_WRAP))
    verifiableCredentialObject.put("proof_req", Base64.encodeToString(proof.proofRequestBytes, Base64.NO_WRAP))
    verifiableCredentialObject.put("values", JSONObject(presentedValues))

    return verifiableCredentialObject
}