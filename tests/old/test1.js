const { ApiPromise, WsProvider, Keyring } = require('@polkadot/api');

async function main() {
    const wsProvider = new WsProvider('ws://127.0.0.1:9944');
    const api = await ApiPromise.create({ provider: wsProvider });

    const keyring = new Keyring({ type: 'sr25519' });
    const alice = keyring.addFromUri('//Alice');

    async function submitUnsignedTransaction() {
        const call = api.tx.system.remark('test remark');

        const unsub = await call.signAndSend(alice, { nonce: -1 }, ({ status }) => {
            if (status.isInBlock) {
                console.log(`Included in block with hash ${status.asInBlock}`);
                unsub();
            } else if (status.isFinalized) {
                console.log(`Finalized block hash ${status.asFinalized}`);
                unsub();
            }
        });
    }

    await submitUnsignedTransaction();
    await api.disconnect();
}

main().catch(console.error);
