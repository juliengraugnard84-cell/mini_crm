const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const script = fs.readFileSync(path.join(__dirname, '../static/cotation_form.js'), 'utf8');
const electric = ['C5', 'C4', 'C2'];
const gas = ['T1', 'T2', 'T3', 'T4'];

function select(value = '', meters = false) {
    const field = {value, disabled: false, listeners: {},
        addEventListener(type, handler) { this.listeners[type] = handler; }};
    field.options = ['', ...electric, ...gas].map(value => ({value,
        dataset: value && meters ? {meterEnergy: electric.includes(value) ? 'electricite' : 'gaz'} : {},
        get selected() { return field.value === value; }, hidden: false, disabled: false}));
    return field;
}

function setup({energy = '', meter = '', mode = 'mono', pointEnergy = 'electricite', pointMeter = ''} = {}) {
    const energyField = select(energy);
    const meterField = select(meter, true);
    const pointEnergyField = select(pointEnergy);
    const pointMeterField = select(pointMeter, true);
    const extra = {hidden: false, querySelectorAll: () => [pointMeterField]};
    const cardFields = {
        '[data-point-energy]': pointEnergyField,
        '[data-point-meter-type]': pointMeterField,
        '[data-point-reference-label]': {},
        '[data-point-energy-wrap]': {},
        '[data-point-extra-information]': extra,
    };
    const card = {querySelector: key => cardFields[key] || null,
        querySelectorAll: () => [pointEnergyField, pointMeterField]};
    const list = {querySelector: () => card, querySelectorAll: () => [card]};
    const modeInputs = ['mono', 'multi'].map(value => ({value, checked: value === mode}));
    const root = {querySelectorAll: () => modeInputs,
        querySelector: key => key === '[data-delivery-points-list]' ? list : null,
        addEventListener() {}};
    const sections = ['electricite', 'gaz'].map(energySection => ({dataset: {energySection},
        classList: {toggle() {}}, querySelectorAll: () => []}));
    const globalPanel = {querySelectorAll: () => [meterField]};
    const form = {
        querySelector: key => ({'[data-energy-select]': energyField,
            '[data-meter-type-select]': meterField, '[data-delivery-points-root]': root}[key] || null),
        querySelectorAll: key => key === '[data-energy-section]' ? sections
            : key === '[data-global-complementary-information]' ? [globalPanel] : [],
    };
    const context = vm.createContext({document: {addEventListener() {}}});
    vm.runInContext(script, context);
    context.initCotationForm(form);
    return {energyField, meterField, pointMeterField,
        changeEnergy(value) { energyField.value = value; energyField.listeners.change(); }};
}

function available(field) {
    return field.options.filter(option => option.value && !option.disabled && !option.hidden).map(option => option.value);
}

test('meter choices remain usable before an energy is selected', () => {
    const form = setup();
    assert.deepEqual(available(form.meterField), [...electric, ...gas]);
    assert.equal(form.meterField.disabled, false);
});
test('electricity and gas each offer their meter types', () => {
    assert.deepEqual(available(setup({energy: 'electricite'}).meterField), electric);
    assert.deepEqual(available(setup({energy: 'gaz'}).meterField), gas);
});
test('mixed energy offers both families', () => {
    assert.deepEqual(available(setup({energy: 'elec_gaz'}).meterField), [...electric, ...gas]);
});
test('an existing selection survives reopening a request with no global energy', () => {
    const form = setup({meter: 'T4'});
    assert.equal(form.meterField.value, 'T4');
    form.changeEnergy('gaz');
    assert.equal(form.meterField.value, 'T4');
});
test('changing energy resets incompatible choices and re-enables the correct choices', () => {
    const form = setup({energy: 'electricite', meter: 'C4'});
    form.changeEnergy('gaz');
    assert.equal(form.meterField.value, '');
    assert.deepEqual(available(form.meterField), gas);
    form.changeEnergy('');
    assert.deepEqual(available(form.meterField), [...electric, ...gas]);
});
test('multisite meters follow each site energy instead of the global filter', () => {
    const form = setup({energy: 'gaz', mode: 'multi', pointEnergy: 'electricite', pointMeter: 'C2'});
    assert.deepEqual(available(form.pointMeterField), electric);
    assert.equal(form.pointMeterField.value, 'C2');
    assert.equal(form.pointMeterField.disabled, false);
    assert.equal(form.meterField.disabled, true);
});
test('gas multisite meters are enabled and preserve their saved value', () => {
    const form = setup({energy: 'elec_gaz', mode: 'multi', pointEnergy: 'gaz', pointMeter: 'T3'});
    assert.deepEqual(available(form.pointMeterField), gas);
    assert.equal(form.pointMeterField.value, 'T3');
    assert.equal(form.pointMeterField.disabled, false);
});
