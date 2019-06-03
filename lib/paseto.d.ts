declare namespace Paseto {
    interface IPasetoKey<P extends IProtocol> {
        /**
         * complete construction asynchronously
         */
        inject(rkey: Buffer): Promise<void>;
        inject(rkey: Buffer, cb: (err: Error) => void): void;

        /**
         * complete construction asynchronously using base64 encoded key
         */
        base64(skey: string): Promise<void>;
        base64(skey: string, cb: (err: Error) => void): void;

        /**
         * complete construction asynchronously using hex encoded key
         */
        hex(skey: string): Promise<void>;
        hex(skey: string, cb: (err: Error) => void): void;

        /**
         * complete construction asynchronously, generating key
         */
        generate(): Promise<void>;
        generate(cb: (err: Error) => void): void;

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

    interface IPasetoKeyV1 extends IPasetoKey<V1> {}
    interface IPasetoKeyV2 extends IPasetoKey<V2> {}

    /**
     * private key for asymmetric cryptography
     */
    export class PrivateKey<P extends IProtocol> implements IPasetoKey<P> {
        constructor(proto: P);

        public inject(rkey: Buffer): Promise<void>;
        public inject(rkey: Buffer, cb: (err: Error) => void): void;

        public base64(skey: string): Promise<void>;
        public base64(skey: string, cb: (err: Error) => void): void;

        public hex(skey: string): Promise<void>;
        public hex(skey: string, cb: (err: Error) => void): void;

        public generate(): Promise<void>;
        public generate(cb: (err: Error) => void): void;

        public protocol(): P;
        public encode(): string;
        public raw(): Buffer;

        /**
         * return the corresponding public key object
         */
        public public(): Promise<PublicKey<P>>;
        public public(cb: (err: Error, key: PublicKey<P>) => void): void;
    }

    /**
     * public key for asymmetric cryptography
     */
    export class PublicKey<P extends IProtocol> implements IPasetoKey<P> {
        constructor(proto: P);

        public inject(rkey: Buffer): Promise<void>;
        public inject(rkey: Buffer, cb: (err: Error) => void): void;

        public base64(skey: string): Promise<void>;
        public base64(skey: string, cb: (err: Error) => void): void;

        public hex(skey: string): Promise<void>;
        public hex(skey: string, cb: (err: Error) => void): void;

        public generate(): Promise<void>;
        public generate(cb: (err: Error) => void): void;

        public protocol(): P;
        public encode(): string;
        public raw(): Buffer;
    }

    /**
     * secret key for symmetric cryptography
     */
    export class SymmetricKey<P extends IProtocol> implements IPasetoKey<P> {
        constructor(proto: P);

        public inject(rkey: Buffer): Promise<void>;
        public inject(rkey: Buffer, cb: (err: Error) => void): void;

        public base64(skey: string): Promise<void>;
        public base64(skey: string, cb: (err: Error) => void): void;

        public hex(skey: string): Promise<void>;
        public hex(skey: string, cb: (err: Error) => void): void;

        public generate(): Promise<void>;
        public generate(cb: (err: Error) => void): void

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
        private(): Promise<PrivateKey<this>>;
        private(cb: (err: Error, key: PrivateKey<this>) => void): void

        /**
         * generate a symmetric key for use with the protocol
         */
        symmetric(): Promise<SymmetricKey<this>>;
        symmetric(cb: (err: Error, key: SymmetricKey<this>) => void): void

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
        encrypt(data: Buffer|string, key: SymmetricKey<this>, footer: Buffer|string|undefined, cb: (err: Error, token: string) => void): void

        /**
         * symmetric authenticated decryption
         */
        decrypt(token: string, key: SymmetricKey<this>, footer?: Buffer|string): Promise<string>;
        decrypt(token: string, key: SymmetricKey<this>, footer: Buffer|string|undefined, cb: (err: Error, data: string) => void): void;

        /**
         * asymmetric authentication
         */
        sign(data: Buffer|string, key: PrivateKey<this>, footer?: Buffer|string): Promise<string>;
        sign(data: Buffer|string, key: PrivateKey<this>, footer: Buffer|string|undefined, cb: (err: Error, token: string) => void): void;

        /**
         * asymmetric authentication
         */
        verify(token: string, key: PublicKey<this>, footer?: Buffer|string): Promise<string>;
        verify(token: string, key: PublicKey<this>, footer: Buffer|string|undefined, cb: (err: Error, data: string) => void): void;
    }

    /**
     * protocol version 1
     */
    export class V1 implements IProtocol {
        public private(): Promise<PrivateKey<this>>;
        public private(cb: (err: Error, key: PrivateKey<this>) => void): void

        public symmetric(): Promise<SymmetricKey<this>>;
        public symmetric(cb: (err: Error, key: SymmetricKey<this>) => void): void

        public repr(): 'v1';
        public sklength(): number;

        public encrypt(data: Buffer|string, key: SymmetricKey<this>, footer?: Buffer|string): Promise<string>;
        public encrypt(data: Buffer|string, key: SymmetricKey<this>, footer: Buffer|string|undefined, cb: (err: Error, token: string) => void): void

        public decrypt(token: string, key: SymmetricKey<this>, footer?: Buffer|string): Promise<string>;
        public decrypt(token: string, key: SymmetricKey<this>, footer: Buffer|string|undefined, cb: (err: Error, data: string) => void): void;

        public sign(data: Buffer|string, key: PrivateKey<this>, footer?: Buffer|string): Promise<string>;
        public sign(data: Buffer|string, key: PrivateKey<this>, footer: Buffer|string|undefined, cb: (err: Error, token: string) => void): void;

        public verify(token: string, key: PublicKey<this>, footer?: Buffer|string): Promise<string>;
        public verify(token: string, key: PublicKey<this>, footer: Buffer|string|undefined, cb: (err: Error, data: string) => void): void;
    }

    /**
     * protocol version 2
     */
    export class V2 implements IProtocol {
        public private(): Promise<PrivateKey<this>>;
        public private(cb: (err: Error, key: PrivateKey<this>) => void): void

        public symmetric(): Promise<SymmetricKey<this>>;
        public symmetric(cb: (err: Error, key: SymmetricKey<this>) => void): void

        public repr(): 'v2';
        public sklength(): number;

        public encrypt(data: Buffer|string, key: SymmetricKey<this>, footer?: Buffer|string): Promise<string>;
        public encrypt(data: Buffer|string, key: SymmetricKey<this>, footer: Buffer|string|undefined, cb: (err: Error, token: string) => void): void

        public decrypt(token: string, key: SymmetricKey<this>, footer?: Buffer|string): Promise<string>;
        public decrypt(token: string, key: SymmetricKey<this>, footer: Buffer|string|undefined, cb: (err: Error, data: string) => void): void;

        public sign(data: Buffer|string, key: PrivateKey<this>, footer?: Buffer|string): Promise<string>;
        public sign(data: Buffer|string, key: PrivateKey<this>, footer: Buffer|string|undefined, cb: (err: Error, token: string) => void): void;

        public verify(token: string, key: PublicKey<this>, footer?: Buffer|string): Promise<string>;
        public verify(token: string, key: PublicKey<this>, footer: Buffer|string|undefined, cb: (err: Error, data: string) => void): void;
    }
}

export = Paseto;
