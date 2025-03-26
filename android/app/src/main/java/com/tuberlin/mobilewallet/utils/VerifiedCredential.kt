package com.tuberlin.mobilewallet.utils

import com.google.gson.annotations.SerializedName

data class WalletCredential(
    @SerializedName("iat") var iat: Number,
    @SerializedName("iss") var iss: String,
    @SerializedName("sub") var sub: String,
    @SerializedName("exp") var exp: Number,
    @SerializedName("nbf") var nbf: Number,
    @SerializedName("jti") var jti: String,
    @SerializedName("vc") var vc: VerifiedCredential,
    @SerializedName("nonce") var nonce: String,
    @SerializedName("signed_nonce") var signedNonce: String,
    @SerializedName("bbs_dpk") var bbsDpk: String,
    @SerializedName("validity_identifier") var validityIdentifier: String,
    @SerializedName("total_messages") var totalMessages: Number
) {
    data class VerifiedCredential(
        @SerializedName("@context") var context: List<String>,
        @SerializedName("type") var type: List<String>,
        @SerializedName("id") var id: String,
        @SerializedName("issuer") var issuer: String,
        @SerializedName("issuanceDate") var issuanceDate: String,
        @SerializedName("validFrom") var validFrom: String,
        @SerializedName("credentialSubject") var credentialSubject: CredentialSubject,
        @SerializedName("credentialSchema") var credentialSchema: CredentialSchema,
        @SerializedName("expirationDate") var expirationDate: String
    ) {
        data class CredentialSubject(
            @SerializedName("id") var id: String?,
            @SerializedName("firstName") var firstName: String,
            @SerializedName("lastName") var lastName: String,
            @SerializedName("issuanceCount") var issuanceCount: String,
            @SerializedName("image") var image: String,
            @SerializedName("studentId") var studentId: String,
            @SerializedName("studentIdPrefix") var studentIdPrefix: String,
            @SerializedName("theme") var theme: Theme
        ) {
            data class Theme(
                @SerializedName("name") var name: String,
                @SerializedName("icon") var icon: String,
                @SerializedName("bgColorCard") var bgColorCard: String,
                @SerializedName("bgColorSectionTop") var bgColorSectionTop: String,
                @SerializedName("bgColorSectionBot") var bgColorSectionBot: String,
                @SerializedName("fgColorTitle") var fgColorTitle: String
            )
        }

        data class CredentialSchema(
            @SerializedName("id") var id: String,
            @SerializedName("type") var type: String,
        )
    }
}
