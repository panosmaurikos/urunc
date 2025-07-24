const spellcheckPlugin = require('@somehow-digital/commitlint-plugin-spellcheck').default;

module.exports = {
  extends: ['@commitlint/config-conventional'],
  plugins: [spellcheckPlugin ],
  rules: {
	'header-max-length': [2, 'always', 72],
	'body-max-line-length': [2, 'always', 80],
	'subject-case': [2, 'never', ['start-case', 'pascal-case', 'upper-case']],
	'trailer-exists': [2, 'always', 'Signed-off-by:'],
	'spellcheck/subject': [2, 'always'],
	'spellcheck/body': [2, 'always'],
	'spellcheck/type': [2, 'always'],
	'spellcheck/footer': [0, 'always']
  },
  parserPreset: {
    parserOpts: {
      noteKeywords: ['Signed-off-by', 'PR'],
    },
  },
  spellcheck: {
    config: "./.cspell.json",
    skipWords: ['commitlint'], // We add words we would like to ignore here
    suggestions: true,
  },
};
