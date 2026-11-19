'use strict';
const path = require('node:path');
const fs = require('node:fs');
const themed = process.env.PLUM_TEST_THEME === 'plum';

exports.templatePath = name => {
    const original = path.join(__dirname, '../webapp/app/templates', name);
    const override = path.join(__dirname, '../webapp/app/templates/themes/plum', name);
    return themed && fs.existsSync(override) ? override : original;
};
exports.tagRendererPath = () => path.join(__dirname, '../webapp/app/static', themed ? 'themes/plum/ip_tag_enrichment.js' : 'js/ip_tag_enrichment.js');
exports.isHidden = element => typeof element.hidden === 'boolean' ? element.hidden : element.style.display === 'none';
