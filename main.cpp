#include <iostream>
#include <openfhe.h>
#include <math/dftransform.h>
#include <utils/parmfactory.h>
#include <omp.h>

using namespace lbcrypto;


int main() {
    std::cout << "Hello, World!" << std::endl;

    std::shared_ptr<ILDCRTParams<BigInteger>> parms = GenerateDCRTParams<BigInteger>(1024,
                                                                                     1,59);
    DCRTPoly plaintextParams = DCRTPoly(parms,EVALUATION);
    plaintextParams.SetValuesToZero();
    DiscreteFourierTransform::Initialize(plaintextParams.GetRingDimension() * 2, plaintextParams.GetRingDimension() / 2);
    CCParams<CryptoContextCKKSRNS> CKKSparameters;
    CKKSparameters.SetMultiplicativeDepth(1);
    CKKSparameters.SetScalingModSize(40);
    //plaintextParams.GetModulus().GetLengthForBase(2)
    CKKSparameters.SetBatchSize(plaintextParams.GetRingDimension()/2);


    CKKSparameters.SetScalingTechnique(FIXEDAUTO);


    //CKKSparameters.SetPlaintextModulus(plaintextParams.GetModulus().ConvertToInt());
    CryptoContext<DCRTPoly> CKKSContext = GenCryptoContext(CKKSparameters);
    CKKSContext->GetCryptoParameters()->SetElementParams(plaintextParams.GetParams());
    std::vector<double> noisy_input(plaintextParams.GetRingDimension()/2,6);
    std::cout << noisy_input << std::endl;

    Plaintext packed_plaintext = CKKSContext->MakeCKKSPackedPlaintext(noisy_input);

    packed_plaintext->Encode();
    DCRTPoly poly_result = packed_plaintext->GetElement<DCRTPoly>();

    Plaintext decrypted = CKKSContext->GetPlaintextForDecrypt(CKKS_PACKED_ENCODING,
                                                              plaintextParams.GetParams(), CKKSContext->GetEncodingParams());

    poly_result.SetFormat(COEFFICIENT);
    decrypted->GetElement<NativePoly>() = poly_result.GetElementAtIndex(0);
    decrypted->GetElement<Poly>() = poly_result.CRTInterpolate();

    auto decryptedCKKS = std::dynamic_pointer_cast<CKKSPackedEncoding>(decrypted);

    decryptedCKKS->SetNoiseScaleDeg(1); //2
    decryptedCKKS->SetLevel(1); // 1
    decryptedCKKS->SetScalingFactor(40); // 40
    decryptedCKKS->SetSlots(poly_result.GetRingDimension()/2); //which is the N/2
    decryptedCKKS->Decode(1,40,FIXEDAUTO,CKKSparameters.GetExecutionMode());
    //std::cout << Decode(*decryptedCKKS.get(),1, 40, NORESCALE, EXEC_EVALUATION) << std::endl;

    std::vector<double> packed_result = decryptedCKKS->GetRealPackedValue();
    std::cout << packed_result << std::endl;
    return 0;
}
