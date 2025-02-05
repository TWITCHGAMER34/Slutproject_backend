exports.up = function(knex) {
    return knex.schema.createTable('sessions', function(table) {
        table.string('sid').primary();
        table.text('sess');
        table.integer('expired');
    });
};

exports.down = function(knex) {
    return knex.schema.dropTable('sessions');
}
