declare namespace Paseto {
    interface IPasetoKey<P extends IProtocol> {
        /**
         * complete construction asynchronously
         */
        inject(rkey: Buffer): Promise<void>;

        /**
         * complete construction asynchronously using base64 encoded key
         */
        base64(skey: string): Promise<void>;

        /**
         * complete construction asynchronously using hex encoded key
         */
        hex(skey: string): Promise<void>;

        /**
         * complete construction asynchronously, generating key
         */
        generate(): Promise<void>;

        /**
         * return the underlying protocol object
         */
        protocol(): P;

        /**
         * encode the raw key as b64url
         */
        encode(): string;

        /**
         * return the raw key buffer
         */
        raw(): Buffer;
    }

    /**
     * private key for asymmetric cryptography
     */
    export class PrivateKey<P extends IProtocol> implements IPasetoKey<P> {
        constructor(proto: P);
        public inject(rkey: Buffer): Promise<void>;
        public base64(skey: string): Promise<void>;
        public hex(skey: string): Promise<void>;
        public generate(): Promise<void>;
        public protocol(): P;
        public encode(): string;
        public raw(): Buffer;
    }

    /**
     * public key for asymmetric cryptography
     */
    export class PublicKey<P extends IProtocol> implements IPasetoKey<P> {
        constructor(proto: P);
        public inject(rkey: Buffer): Promise<void>;
        public base64(skey: string): Promise<void>;
        public hex(skey: string): Promise<void>;
        public generate(): Promise<void>;
        public protocol(): P;
        public encode(): string;
        public raw(): Buffer;

        /**
         * return the corresponding public key object
         */
        public public(): Promise<PublicKey<P>>;
    }

    /**
     * secret key for symmetric cryptography
     */
    export class SymmetricKey<P extends IProtocol> implements IPasetoKey<P> {
        constructor(proto: P);
        public inject(rkey: Buffer): Promise<void>;
        public base64(skey: string): Promise<void>;
        public hex(skey: string): Promise<void>;
        public generate(): Promise<void>;
        public protocol(): P;
        public encode(): string;
        public raw(): Buffer;
    }

    namespace PrivateKey {
        /**
         * shortcut for new PrivateKey(new V1())
         */
        export class V1 extends PrivateKey<Paseto.V1> {
            constructor();
        }

        /**
         * shortcut for new PrivateKey(new V2())
         */
        export class V2 extends PrivateKey<Paseto.V2> {
            constructor();
        }
    }

    namespace PublicKey {
        /**
         * shortcut for new PublicKey(new V1())
         */
        export class V1 extends PublicKey<Paseto.V1> {
            constructor();
        }

        /**
         * shortcut for new PublicKey(new V2())
         */
        export class V2 extends PublicKey<Paseto.V2> {
            constructor();
        }
    }

    namespace SymmetricKey {
        /**
         * shortcut for new SymmetricKey(new V1())
         */
        export class V1 extends SymmetricKey<Paseto.V1> {
            constructor();
        }

        /**
         * shortcut for new SymmetricKey(new V2())
         */
        export class V2 extends SymmetricKey<Paseto.V2> {
            constructor();
        }
    }

    interface IProtocol {
        /**
         * generate a private key for use with the protocol
         */
        pk(): Promise<PrivateKey<this>>;

        /**
         * generate a symmetric key for use with the protocol
         */
        sk(): Promise<SymmetricKey<this>>;

        /**
         * get protocol representation
         */
        repr(): string;

        /**
         * get symmetric key length
         */
        sklength(): number;

        /**
         * symmetric authenticated encryption
         */
        encrypt(data: Buffer|string, key: SymmetricKey<this>, footer?: Buffer|string): Promise<string>;

        /**
         * symmetric authenticated decryption
         */
        decrypt(token: string, key: SymmetricKey<this>, footer?: Buffer|string): Promise<string>;

        /**
         * asymmetric authentication
         */
        sign(data: Buffer|string, key: PrivateKey<this>, footer?: Buffer|string): Promise<string>;

        /**
         * asymmetric authentication
         */
        verify(token: string, key: PublicKey<this>, footer?: Buffer|string): Promise<string>;
    }

    /**
     * protocol version 1
     */
    export class V1 implements IProtocol {
        public pk(): Promise<PrivateKey<this>>;
        public sk(): Promise<SymmetricKey<this>>;
        public repr(): string;
        public sklength(): number;
        public encrypt(data: Buffer|string, key: SymmetricKey<this>, footer?: Buffer|string): Promise<string>;
        public decrypt(token: string, key: SymmetricKey<this>, footer?: Buffer|string): Promise<string>;
        public sign(data: Buffer|string, key: PrivateKey<this>, footer?: Buffer|string): Promise<string>;
        public verify(token: string, key: PublicKey<this>, footer?: Buffer|string): Promise<string>;
    }

    /**
     * protocol version 2
     */
    export class V2 implements IProtocol {
        public pk(): Promise<PrivateKey<this>>;
        public sk(): Promise<SymmetricKey<this>>;
        public repr(): string;
        public sklength(): number;
        public encrypt(data: Buffer|string, key: SymmetricKey<this>, footer?: Buffer|string): Promise<string>;
        public decrypt(token: string, key: SymmetricKey<this>, footer?: Buffer|string): Promise<string>;
        public sign(data: Buffer|string, key: PrivateKey<this>, footer?: Buffer|string): Promise<string>;
        public verify(token: string, key: PublicKey<this>, footer?: Buffer|string): Promise<string>;
    }
}

export = Paseto;
