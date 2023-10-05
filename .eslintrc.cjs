/* eslint-env node */
module.exports = {
    extends: [
        'eslint:recommended',
        'plugin:@typescript-eslint/recommended',
        'plugin:@typescript-eslint/stylistic'
    ],
    parser: '@typescript-eslint/parser',
    plugins: ['@typescript-eslint'],
    rules: {
        "no-extra-semi": "off",
        "@typescript-eslint/no-extra-semi": "error",

        "semi": "off",
        "@typescript-eslint/semi": "error"
    },
    root: true,
};
