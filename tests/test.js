const { ApiPromise, WsProvider, Keyring } = require('@polkadot/api');

async function main() {
    try {
        // Connect to the local node
        const wsProvider = new WsProvider('ws://127.0.0.1:9944');
        const api = await ApiPromise.create({ provider: wsProvider });

        // Initialize keyring
        const keyring = new Keyring({ type: 'sr25519' });
        const alice = keyring.addFromUri('//Alice');

        // Function to submit a signed transaction
        async function submitSignedTransaction() {
            const call = api.tx.system.remark('test remark');

            // Sign and send the transaction
            const unsub = await call.signAndSend(alice, ({ status }) => {
                if (status.isInBlock) {
                    console.log(`Included in block with hash ${status.asInBlock}`);
                    unsub();
                } else if (status.isFinalized) {
                    console.log(`Finalized block hash ${status.asFinalized}`);
                    unsub();
                }
            });
        }

        // Run the test
        await submitSignedTransaction();

        // Disconnect from the node
        await api.disconnect();
    } catch (error) {
        console.error('Error in main function:', error);
    }
}

main().catch(console.error);

