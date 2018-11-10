# Identity Verification on the Tangle

Using the tangle and the bitcoin signature scheme, a proof of concept has been developed.

The limitation of the iota tangle are that signed zero value transactions do not exist, and addresses change frequently. Thus using Bitcoin addresses which are known and familiar verifiers of identity can sign on the authenticity of documents. 

## How it works

An entity with a known bitcoin address can review documentation, and sign as to their contents. For example, John Smith has a passport that he is required to show to a bank before he can open up a loan. The bank reviews the documents submitted and creates a transaction to be stored on the iota tangle. 

This transaction is signed with the private key of the bank, and contains all of John's information in text format. This example it is only his name 'John Smith'. The bank has verified his information by cross checking his passport, and shares with him the public transaction hash and their public key (Bitcoin address).

John later goes to an insurance company which once again is requesting his passport. He now only needs to provide the insurance company with his Name, the TX hash and the Bitcoin address that verified his information. If the insurance company trusts the Banks KYC procedures, they can approve his information without needing his documents to be uploaded again. Thus saving the need to store it! The type of information that can be sent in bundles, includes address, name, ssn and maritial status. 

### Testing

Run
python bitsign.py

Follow the prompts to enter your name.
Enter Name, John Smith. The next available address will be generated from the default seed, and the transaction will be submitted to the tangle. Store the information that has been shared on screen. 

For recovery or verification, enter the details from the transaction and follow the prompts. 
True - Identity verified
False - Identity could not be verified

### Prerequisites and installation

python2

mkdir ~/virtualenvironment
virtualenv ~/virtualenvironment/iota_id
cd ~/virtualenvironment/iota_id/bin
source activate

pip install -r requirements.txt

## Versioning

We use [SemVer](http://semver.org/) for versioning. For the versions available, see the [tags on this repository](https://github.com/your/project/tags). 

## Authors

* **TertiusN** - *Initial work* - [TertiusN](https://github.com/TertiusN)

See also the list of [contributors](https://github.com/your/project/contributors) who participated in this project.

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details

## Acknowledgments

* Electrum for bitcoin signing code base
* Pyota

