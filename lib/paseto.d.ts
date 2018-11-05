declare namespace Paseto {
    interface Key<P extends Protocol> {
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
    export class PrivateKey<P extends Protocol> implements Key<P> {
        constructor(proto: P);
        inject(rkey: Buffer): Promise<void>;
        base64(skey: string): Promise<void>;
        hex(skey: string): Promise<void>;
        generate(): Promise<void>;
        protocol(): P;
        encode(): string;
        raw(): Buffer;
    }

    /**
     * public key for asymmetric cryptography
     */
    export class PublicKey<P extends Protocol> implements Key<P> {
        constructor(proto: P);
        inject(rkey: Buffer): Promise<void>;
        base64(skey: string): Promise<void>;
        hex(skey: string): Promise<void>;
        generate(): Promise<void>;
        protocol(): P;
        encode(): string;
        raw(): Buffer;

        /**
         * return the corresponding public key object
         */
        public(): Promise<PublicKey<P>>;
    }

    /**
     * secret key for symmetric cryptography
     */
    export class SymmetricKey<P extends Protocol> implements Key<P> {
        constructor(proto: P);
        inject(rkey: Buffer): Promise<void>;
        base64(skey: string): Promise<void>;
        hex(skey: string): Promise<void>;
        generate(): Promise<void>;
        protocol(): P;
        encode(): string;
        raw(): Buffer;
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

    interface Protocol {
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
    export class V1 implements Protocol {
        pk(): Promise<PrivateKey<this>>;
        sk(): Promise<SymmetricKey<this>>;
        repr(): string;
        sklength(): number;
        encrypt(data: Buffer|string, key: SymmetricKey<this>, footer?: Buffer|string): Promise<string>;
        decrypt(token: string, key: SymmetricKey<this>, footer?: Buffer|string): Promise<string>;
        sign(data: Buffer|string, key: PrivateKey<this>, footer?: Buffer|string): Promise<string>;
        verify(token: string, key: PublicKey<this>, footer?: Buffer|string): Promise<string>;
    }

    /**
     * protocol version 2
     */
    export class V2 implements Protocol {
        pk(): Promise<PrivateKey<this>>;
        sk(): Promise<SymmetricKey<this>>;
        repr(): string;
        sklength(): number;
        encrypt(data: Buffer|string, key: SymmetricKey<this>, footer?: Buffer|string): Promise<string>;
        decrypt(token: string, key: SymmetricKey<this>, footer?: Buffer|string): Promise<string>;
        sign(data: Buffer|string, key: PrivateKey<this>, footer?: Buffer|string): Promise<string>;
        verify(token: string, key: PublicKey<this>, footer?: Buffer|string): Promise<string>;
    }
}

export = Paseto;
